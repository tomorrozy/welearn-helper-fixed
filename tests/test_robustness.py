"""针对本次健壮性改动的回归测试。

覆盖:
1. 登录跳转 URL 按名解析(不依赖参数下标)
2. 登录 code=-1 的退避重试有上限
3. 页面/接口解析失败抛出可读的 WelearnError,而不是 AttributeError/KeyError
4. 单章节异常不再终止整批任务
"""
import json
import threading

import pytest

from tests.fakes import FakeResponse, FakeSession
import welearn_common
import welearn_accuracy
import welearn_time
from welearn_common import LoginError, WelearnError


def loc_url(**params):
    """按给定字典拼一个登录跳转地址(参数顺序由调用方控制)。"""
    return ("https://sso.sflep.com/idsvr/connect/authorize?"
            + "&".join(f"{k}={v}" for k, v in params.items()))


def make_login_session(location, code=0):
    fake = FakeSession()
    fake.routes["https://welearn.sflep.com/user/prelogin.aspx"] = \
        FakeResponse(headers={"Location": location} if location else {})
    fake.routes["https://sso.sflep.com/idsvr/account/login"] = \
        FakeResponse(json_data={"code": code, "data": "/next"})
    fake.routes["https://sso.sflep.com/idsvr/next"] = FakeResponse(text="ok")
    return fake


class TestLoginUrlParsing:
    def test_param_order_does_not_matter(self):
        """原实现按下标取 split("&")[4]/[6],参数顺序一变就 IndexError。"""
        loc = loc_url(state="ST", client_id="welearn_web",
                      code_challenge="CH", redirect_uri="r")
        fake = make_login_session(loc, code=0)
        logs = []
        welearn_common.login(fake, "user", "pw", on_log=logs.append)
        assert any("登录成功" in m for m in logs)

    def test_missing_param_raises_readable_error(self):
        loc = loc_url(state="ST", client_id="welearn_web")   # 缺 code_challenge
        fake = make_login_session(loc, code=0)
        with pytest.raises(LoginError) as exc:
            welearn_common.login(fake, "user", "pw")
        assert "code_challenge" in str(exc.value)

    def test_empty_location_raises_login_error(self):
        fake = make_login_session(None, code=0)
        with pytest.raises(LoginError):
            welearn_common.login(fake, "user", "pw")


class TestLoginRetry:
    def test_retry_is_bounded(self, monkeypatch):
        """code=-1 时原实现无间隔无限重试,会高频轰击 SSO。"""
        monkeypatch.setattr(welearn_common, "LOGIN_RETRY_DELAY", 0)
        loc = loc_url(code_challenge="CH", state="ST")
        fake = make_login_session(loc, code=-1)
        with pytest.raises(LoginError):
            welearn_common.login(fake, "user", "pw")
        posts = [r for r in fake.requests if r[0] == "POST"]
        assert len(posts) == welearn_common.LOGIN_MAX_ATTEMPTS

    def test_recovers_on_later_attempt(self, monkeypatch):
        monkeypatch.setattr(welearn_common, "LOGIN_RETRY_DELAY", 0)
        loc = loc_url(code_challenge="CH", state="ST")
        fake = make_login_session(loc)
        calls = {"n": 0}

        def login_route(url, data):
            calls["n"] += 1
            return FakeResponse(json_data={"code": -1 if calls["n"] == 1 else 0,
                                           "data": "/next"})

        fake.routes["https://sso.sflep.com/idsvr/account/login"] = login_route
        logs = []
        welearn_common.login(fake, "user", "pw", on_log=logs.append)
        assert calls["n"] == 2
        assert any("登录成功" in m for m in logs)

    def test_stop_event_during_retry_raises(self):
        loc = loc_url(code_challenge="CH", state="ST")
        fake = make_login_session(loc, code=-1)
        stop = threading.Event()
        stop.set()
        with pytest.raises(WelearnError):
            welearn_common.login(fake, "user", "pw", stop_event=stop)


class TestPageParsing:
    def test_get_course_ids_missing_fields(self):
        fake = FakeSession()
        fake.routes["https://welearn.sflep.com/student/course_info.aspx"] = \
            FakeResponse(text="<html>登录已失效</html>")
        with pytest.raises(WelearnError) as exc:
            welearn_common.get_course_ids(fake, "1")
        assert "解析失败" in str(exc.value)

    def test_fetch_units_non_json(self):
        fake = FakeSession()
        fake.routes["https://welearn.sflep.com/ajax/StudyStat.aspx"] = \
            FakeResponse(text="<html>出错了</html>")
        with pytest.raises(WelearnError) as exc:
            welearn_common.fetch_units(fake, "1", "2")
        assert "JSON" in str(exc.value)

    def test_fetch_units_missing_info(self):
        fake = FakeSession()
        fake.routes["https://welearn.sflep.com/ajax/StudyStat.aspx"] = \
            FakeResponse(json_data={"code": 0})
        with pytest.raises(WelearnError) as exc:
            welearn_common.fetch_units(fake, "1", "2")
        assert "info" in str(exc.value)


def _ok_cmi_ajax():
    cmi = {"score": {"scaled": ""}, "completion_status": "unknown",
           "progress_measure": "0", "total_time": "0", "session_time": "0"}
    return FakeResponse(json_data={"comment": json.dumps({"cmi": cmi})})


class TestGenerateCipherText:
    """登录加密的时间戳校验位。

    原实现 T1 = int((T0/100)*100 + remainder),末两位变成 (T0+remainder) 的末两位,
    与校验值无关;服务端校验不过会固定返回 code=-1「请求参数无效」。
    """

    NOW = 1794046490653

    def _expected_remainder(self, pwd: str) -> int:
        v = (self.NOW >> 16) & 0xFF
        for b in pwd.encode("utf-8"):
            v ^= b
        return v % 100

    def test_t1_last_two_digits_equal_checksum(self):
        pwd = "fixture-pass-9"
        _, t1 = welearn_common.generate_cipher_text(pwd, self.NOW)
        assert t1 % 100 == self._expected_remainder(pwd), \
            "T1 末两位必须是校验值(旧公式会算成 (T0+校验值) 的末两位)"

    def test_t1_uses_floor_to_hundred(self):
        pwd = "abc123"
        r = self._expected_remainder(pwd)
        expected = (self.NOW // 100) * 100 + r
        _, t1 = welearn_common.generate_cipher_text(pwd, self.NOW)
        assert t1 == expected

    def test_payload_is_timestamp_star_hex_password(self):
        import base64
        pwd = "p@ss中文"
        e, t1 = welearn_common.generate_cipher_text(pwd, self.NOW)
        decoded = base64.b64decode(e.encode("ascii")).decode("utf-8")
        assert decoded == f"{t1}*" + pwd.encode("utf-8").hex()


class TestTimeChapterIsolation:
    def _make_task(self, fake, chapters):
        task = welearn_time.TimeTask("u", "p", on_log=lambda m: None)
        task.session = fake
        task.cid, task.uid, task.classid = "C1", "U1", "K1"
        task.units = [{"unitname": "U1", "name": "Unit One"}]
        task.request_interval = 0
        fake.routes["https://welearn.sflep.com/ajax/StudyStat.aspx?action=scoLeaves"] = \
            FakeResponse(json_data={"info": chapters})
        return task

    def test_bad_chapter_does_not_abort_batch(self):
        """某个章节接口返回非 JSON 时,后续章节仍应继续刷。"""
        fake = FakeSession()
        chapters = [{"id": 1, "location": "BadChapter", "learntime": 0},
                    {"id": 2, "location": "GoodChapter", "learntime": 0}]

        def ajax(url, data):
            if data and data.get("scoid") == 1 and data.get("action") == "getscoinfo_v7":
                return FakeResponse(text="<html>不是 JSON</html>")
            return _ok_cmi_ajax()

        fake.routes["https://welearn.sflep.com/Ajax/SCO.aspx"] = ajax
        task = self._make_task(fake, chapters)
        result = task.run(0, 1)

        assert result["total"] == 2
        assert result["failed"] == 1
        assert result["succeed"] == 1
        assert result["errors"] == ["BadChapter"]


class TestAccuracyChapterIsolation:
    def _make_task(self, fake, chapters):
        task = welearn_accuracy.AccuracyTask("u", "p", on_log=lambda m: None)
        task.session = fake
        task.cid, task.uid, task.classid = "C1", "U1", "K1"
        task.units = [{"unitname": "U1", "name": "Unit One", "visible": "true"}]

        def scoleaves(url, data):
            if "unitidx=0" in url:
                return FakeResponse(json_data={"info": chapters})
            return FakeResponse(text="出错了")

        fake.routes["https://welearn.sflep.com/ajax/StudyStat.aspx?action=scoLeaves"] = scoleaves
        return task

    def test_post_exception_does_not_abort_unit(self):
        fake = FakeSession()
        chapters = [{"id": 1, "location": "Bad", "isvisible": "true", "iscomplete": "未完成"},
                    {"id": 2, "location": "Good", "isvisible": "true", "iscomplete": "未完成"}]

        def ajax(url, data):
            if data and data.get("scoid") == 1:
                raise RuntimeError("网络中断")
            return FakeResponse(text='{"ret":0}')

        fake.routes["https://welearn.sflep.com/Ajax/SCO.aspx"] = ajax
        task = self._make_task(fake, chapters)
        result = task.run(1, 100)

        assert result["way1_succeed"] == 1
        assert result["way1_failed"] == 1
        assert result["way2_succeed"] == 1
        assert result["way2_failed"] == 1

    def test_bad_sco_leaves_json_skips_unit(self):
        fake = FakeSession()
        fake.routes["https://welearn.sflep.com/ajax/StudyStat.aspx?action=scoLeaves"] = \
            FakeResponse(text="<html>no json</html>")
        fake.routes["https://welearn.sflep.com/Ajax/SCO.aspx"] = FakeResponse(text='{"ret":0}')
        task = welearn_accuracy.AccuracyTask("u", "p", on_log=lambda m: None)
        task.session = fake
        task.cid, task.uid, task.classid = "C1", "U1", "K1"
        task.units = [{"unitname": "U1", "name": "Unit One", "visible": "true"}]
        result = task.run(1, 100)
        assert result["way1_succeed"] == 0
        assert result["way1_failed"] == 0
