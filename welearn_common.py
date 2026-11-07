"""Welearn_helper 共享核心:异常、登录加密、参数解析、登录与课程查询(CLI 与 GUI 共用)。"""
import base64
import re
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import unquote, urlparse

import tls_client

AJAX_BASE = "https://welearn.sflep.com"

# 单次 HTTP 请求超时(秒)。库默认 30s,配合登录重试会把单次 /api/login 拖到 150s+。
REQUEST_TIMEOUT = 10

# 登录链路只允许跟随到这些主机,防止服务端返回的 Location 把请求导向任意地址。
ALLOWED_REDIRECT_HOSTS = frozenset({"sso.sflep.com", "welearn.sflep.com"})

# 登录校验失败(服务端返回 code=-1,通常是本机与服务器时间偏差)时的重试策略。
# 原实现无间隔、无上限地空转重试,会对 SSO 造成高频请求,有被风控的风险。
LOGIN_MAX_ATTEMPTS = 5
LOGIN_RETRY_DELAY = 0.5

# 登录成功后跟随重定向的最大跳数(防止站点异常时无限跳转)
MAX_REDIRECTS = 10


class LoginError(Exception):
    """账号密码错误或登录流程失败"""


class WelearnError(Exception):
    """业务流程异常(响应异常、空课程列表、被用户停止等)"""


def new_session() -> tls_client.Session:
    session = tls_client.Session(client_identifier="chrome_120", debug=False)
    session.timeout_seconds = REQUEST_TIMEOUT   # 会话级默认超时(库支持覆盖)
    return session


def to_hex_byte_array(byte_array) -> str:
    return ''.join([f'{byte:02x}' for byte in byte_array])


def generate_cipher_text(password: str, now_ms: Optional[int] = None) -> Tuple[str, int]:
    """复刻前端登录加密。返回 (base64 密文, T1)。

    前端实现(sso.web 包 js.cookie 分块):
        t = Date.now(); v = (t >> 16) & 255; v ^= 每个密码字节
        a = v % 100; T1 = Math.floor(t/100)*100 + a      # 末两位替换为校验值
        payload = T1 + "*" + 密码字节的 hex; btoa(payload)

    历史 bug:原实现写成 int((T0/100)*100 + remainder),浮点乘回来约等于 T0 再加 remainder,
    T1 的末两位与校验值无关。服务端会校验末两位,于是固定返回
    code=-1「请求参数无效」——表现为"密码正确也登不上"。
    """
    T0 = int(round(now_ms if now_ms is not None else time.time() * 1000))
    # 模拟TextEncoder.encode
    P = password.encode('utf-8')
    V = (T0 >> 16) & 0xFF
    for byte in P:
        V ^= byte
    remainder = V % 100
    # 对应 JS: Math.floor(T0/100)*100 + remainder
    T1 = (T0 // 100) * 100 + remainder
    P1 = to_hex_byte_array(P)
    S = f"{T1}*" + P1
    S_encoded = S.encode('utf-8')
    # 模拟btoa
    E = base64.b64encode(S_encoded).decode('utf-8')
    return E, T1


def _check_range(value: int, min_value: Optional[int], max_value: Optional[int]) -> None:
    if min_value is not None and value < min_value:
        raise ValueError(f"取值 {value} 小于允许的最小值 {min_value}")
    if max_value is not None and value > max_value:
        raise ValueError(f"取值 {value} 大于允许的最大值 {max_value}")


def parse_numeric_param(text: str, min_value: Optional[int] = None,
                        max_value: Optional[int] = None) -> Union[int, Tuple[int, int]]:
    """解析 '30' -> 30;'10,30' -> (10, 30);其余抛 ValueError(替代原 eval 用法)。

    min_value / max_value 限定取值范围。原实现只校验「下限≤上限」,负数与超大值
    会原样提交给服务端:正确率会变成负分,时长会拉起一个以天计的等待循环。
    """
    text = text.strip()
    if ',' in text:
        parts = text.split(',')
        if len(parts) != 2:
            raise ValueError(f"格式异常: {text!r}(区间格式为 最小值,最大值)")
        lo, hi = int(parts[0]), int(parts[1])
        if lo > hi:
            raise ValueError(f"格式异常: {text!r}(下限大于上限)")
        _check_range(lo, min_value, max_value)
        _check_range(hi, min_value, max_value)
        return lo, hi
    value = int(text)
    _check_range(value, min_value, max_value)
    return value


def _noop(msg):
    pass


def _check_stop(stop_event: Optional[threading.Event]) -> None:
    if stop_event is not None and stop_event.is_set():
        raise WelearnError("已停止")


def _redirect_param(url: str, name: str) -> str:
    """从登录跳转 URL 的查询串按名取参数。

    原实现用 rurl.split("&")[4]/[6] 按下标取值:站点一旦调整参数顺序就 IndexError。
    这里按浏览器的 URLSearchParams 语义解析——注意 **不用 parse_qs**:
    parse_qs 会把 '+' 解成空格,而浏览器保持 '+' 原样;两者对含 '+' 的值结果不同。
    """
    query = urlparse(url or "").query
    for pair in query.split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        if unquote(key) == name:
            return unquote(value)
    raise LoginError(f"登录跳转地址缺少参数 {name}(站点可能改版或网络异常): {url!r}")


def _check_redirect_target(url: str) -> str:
    """校验重定向目标主机,只允许 sso/welearn 域名。"""
    host = (urlparse(url).netloc or "").split("@")[-1].split(":")[0].lower()
    if host not in ALLOWED_REDIRECT_HOSTS:
        raise LoginError(f"登录跳转目标不在允许范围: {host!r}")
    return url


def _guard_json(response, what: str):
    """会话失效时接口会 302,此时 response.text 为空——先判状态码再解析。"""
    if response.status_code in (301, 302, 303, 307, 308):
        raise WelearnError("登录已失效(服务端返回重定向),请重新登录")
    try:
        payload = response.json()
    except Exception:
        raise WelearnError(f"{what}返回内容不是有效 JSON(可能登录已失效或接口变更)")
    return payload


def _build_authorize_url(code_challenge: str, state: str) -> str:
    return (
        "/connect/authorize/callback?client_id=welearn_web"
        "&redirect_uri=https%3A%2F%2Fwelearn.sflep.com%2Fsignin-sflep"
        "&response_type=code&scope=openid%20profile%20email%20phone%20address"
        f"&code_challenge={code_challenge}&code_challenge_method=S256"
        f"&state={state}&x-client-SKU=ID_NET472&x-client-ver=6.32.1.0"
    )


# 登录入口。loginret 原为 http://,存在登录后跳转被降级到明文的可能(V-011);
# 实测改为 https 后登录链路与课程读取均正常,故切换。
PRELOGIN_URL = ("https://welearn.sflep.com/user/prelogin.aspx"
                "?loginret=https://welearn.sflep.com/user/loginredirect.aspx")


def login(session, user: str, pwd: str,
          on_log: Callable[[str], None] = _noop,
          stop_event: Optional[threading.Event] = None) -> None:
    """在传入的 session 上完成登录;密码错误抛 LoginError,被停止抛 WelearnError。"""
    try:
        _check_stop(stop_event)
        response = session.get(PRELOGIN_URL)
        rurl = response.headers.get("Location")
        if not rurl:
            raise LoginError("登录跳转地址为空(站点可能改版或网络异常)")

        rturl = _build_authorize_url(_redirect_param(rurl, "code_challenge"),
                                     _redirect_param(rurl, "state"))
        on_log("登录中...")

        for attempt in range(1, LOGIN_MAX_ATTEMPTS + 1):
            _check_stop(stop_event)
            enpwd = generate_cipher_text(pwd)
            form_data = {
                "rturl": rturl,
                "account": user,
                "pwd": str(enpwd[0]),
                "ts": str(enpwd[1]),
            }

            response = session.post("https://sso.sflep.com/idsvr/account/login", data=form_data)
            rt_json = response.json()
            code = rt_json.get("code", -1)

            if code == -1:
                # 服务端时间戳校验未通过:退避重试而非空转,并设上限
                if attempt >= LOGIN_MAX_ATTEMPTS:
                    raise LoginError(
                        f"登录校验连续 {LOGIN_MAX_ATTEMPTS} 次未通过,"
                        "通常是本机时间与服务器偏差过大,请校准系统时间后重试")
                on_log(f"登录校验未通过,{LOGIN_RETRY_DELAY}s 后重试 ({attempt}/{LOGIN_MAX_ATTEMPTS})")
                time.sleep(LOGIN_RETRY_DELAY)
                continue

            if code == 1:
                raise LoginError("帐号或密码错误!")

            next_url = "https://sso.sflep.com/idsvr" + rt_json.get("data")

            for _hop in range(MAX_REDIRECTS):
                _check_stop(stop_event)
                _check_redirect_target(next_url)   # 不跟随到非 sflep 主机
                resp = session.get(next_url)
                if resp.status_code in (301, 302, 303, 307, 308):
                    nxt = resp.headers.get("Location", None)
                    if not nxt:
                        break
                    if nxt.startswith("/"):
                        p = urlparse(next_url)
                        nxt = f"{p.scheme}://{p.netloc}{nxt}"
                    next_url = nxt
                else:
                    break

            if code == 0:
                on_log("登录成功!")
                return
    except (LoginError, WelearnError):
        raise
    except Exception as e:
        raise LoginError(f"错误返回,登录失败!错误信息:{e}")


def fetch_courses(session) -> List[dict]:
    response = session.get(
        'https://welearn.sflep.com/ajax/authCourse.aspx?action=gmc',
        headers={'Referer': 'https://welearn.sflep.com/2019/student/index.aspx'})
    payload = _guard_json(response, "课程列表")
    clist = payload.get('clist', []) if isinstance(payload, dict) else []
    if not clist:
        raise WelearnError('发生错误!!!可能是登录错误或没有课程!!!')
    return clist


def get_course_ids(session, cid: str) -> Tuple[str, str]:
    response = session.get(f"https://welearn.sflep.com/student/course_info.aspx?cid={cid}")
    if response.status_code in (301, 302, 303, 307, 308):
        raise WelearnError("登录已失效(服务端返回重定向),请重新登录")
    uid_match = re.search(r'"uid":(.*?),', response.text)
    classid_match = re.search(r'"classid":"(.*?)"', response.text)
    if not uid_match or not classid_match:
        # 原实现直接 .group(1),页面结构变化时抛 AttributeError,信息毫无指向性
        raise WelearnError("课程信息页解析失败(uid/classid 缺失,可能登录已失效或页面改版)")
    return uid_match.group(1), classid_match.group(1)


def _json_info(response, what: str):
    """取接口返回的 info 字段,失败时抛可读的 WelearnError。"""
    payload = _guard_json(response, what)
    if not isinstance(payload, dict) or "info" not in payload:
        raise WelearnError(f"{what}返回缺少 info 字段(接口可能已变更)")
    return payload["info"]


def fetch_units(session, cid: str, uid: str) -> List[dict]:
    response = session.get(
        'https://welearn.sflep.com/ajax/StudyStat.aspx',
        params={'action': 'courseunits', 'cid': cid, 'uid': uid},
        headers={'Referer': 'https://welearn.sflep.com/2019/student/course_info.aspx'})
    return _json_info(response, "课程单元列表")


def normalize_targets(units, sections=None) -> Tuple[bool, Optional[List[int]], Optional[Dict[int, List[int]]]]:
    """解析任务目标为 (是否全部单元, 单元编号列表, {单元编号: [小节编号]})。

    units:   0/None=全部单元; 正整数=单个单元; 非空列表=多个单元
    sections: None/{}=整单元; 正整数=该单元单个小节; {单元编号: [小节编号]}=按单元多选
    非法输入抛 ValueError(界面直接展示给用户)。
    """
    if isinstance(units, str):
        raise ValueError("单元编号格式错误(不支持字符串)")   # "12"会被逐字符迭代成[1,2]
    all_units = units in (0, None)
    if all_units:
        unit_list = None
    elif isinstance(units, int):
        if units < 1:
            raise ValueError("单元编号从1开始")
        unit_list = [units]
    else:
        try:
            unit_list = sorted({int(u) for u in units})
        except (TypeError, ValueError):
            raise ValueError("单元编号格式错误")
        if not unit_list:
            raise ValueError("未选择任何单元(勾选单元或选择全部单元)")
        if unit_list[0] < 1:
            raise ValueError("单元编号从1开始")

    if isinstance(sections, str):
        raise ValueError("小节编号格式错误(不支持字符串)")
    if sections in (None, {}, 0):
        return all_units, unit_list, None
    if all_units:
        raise ValueError("指定小节时请选择具体单元(不能与全部单元同用)")

    if isinstance(sections, dict):
        section_map: Dict[int, List[int]] = {}
        for u, secs in sections.items():
            if isinstance(secs, str):
                raise ValueError("小节编号格式错误(不支持字符串)")
            try:
                uno, sec_list = int(u), [int(s) for s in secs]
            except (TypeError, ValueError):
                raise ValueError("小节编号格式错误")
            sec_list = sorted(set(sec_list))
            if sec_list and sec_list[0] < 1:
                raise ValueError("小节编号从1开始")
            if sec_list:
                section_map[uno] = sec_list
    else:
        try:
            sec = int(sections)
        except (TypeError, ValueError):
            raise ValueError("小节编号格式错误")
        if sec < 1:
            raise ValueError("小节编号从1开始")
        section_map = {u: [sec] for u in unit_list or []}

    if not section_map:
        return all_units, unit_list, None
    for uno in section_map:
        if uno not in (unit_list or []):
            raise ValueError(f"单元{uno}未在选择的单元内,不能为其指定小节")
    return all_units, unit_list, section_map


def fetch_sections(session, cid: str, uid: str, unitidx: int, classid: str) -> List[dict]:
    """只读拉取指定单元的小节列表(scoLeaves,与刷课遍历同一接口;不提交任何数据)"""
    response = session.get(
        f'https://welearn.sflep.com/ajax/StudyStat.aspx?action=scoLeaves&cid={cid}&uid={uid}&unitidx={unitidx}&classid={classid}',
        headers={'Referer': f'https://welearn.sflep.com/2019/student/course_info.aspx?cid={cid}'})
    if "异常" in response.text or "出错了" in response.text:
        raise WelearnError('单元不存在或已到末尾!!!')
    return _json_info(response, "小节列表")
