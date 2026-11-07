"""P0/P1 加固项的回归测试。

对应审计发现:
V-001 Host 校验(防 DNS rebinding)
V-003 参数范围校验
V-004 登录独占(并发双登录)
V-006 会话关闭
V-012 units=null 不得退化为"全部单元"
"""
import pytest

import web_gui
import welearn_accuracy
import welearn_time


class FakeSession:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeTask:
    def __init__(self, username, password, on_log=None, stop_event=None, session=None):
        self.username = username
        self.password = password
        self.on_log = on_log
        self.stop_event = stop_event
        self.session = session or FakeSession()
        self.cid = self.uid = self.classid = ""
        self.units = []

    def login(self):
        pass

    def fetch_courses(self):
        return [{"cid": 11, "per": 60, "name": "课程A"}]

    def fetch_units(self, cid):
        return [{"unitname": "U1", "name": "第一单元", "visible": "true"}]

    def fetch_sections(self, unit_index):
        return [{"location": "U1 > A", "iscomplete": "completed", "isvisible": "true"}]

    def run(self, units, param, sections=None):
        self.last_run_args = (units, param, sections)
        return {"way1_succeed": 1, "way1_failed": 0,
                "way2_succeed": 1, "way2_failed": 0}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(welearn_accuracy, "AccuracyTask", FakeTask)
    monkeypatch.setattr(welearn_time, "TimeTask", FakeTask)
    app, state = web_gui.create_app()
    return app.test_client(), state


def do_login(client, mode="accuracy"):
    c, _ = client
    return c.post("/api/login", json={"username": "u", "password": "p", "mode": mode})


def load_units(client):
    c, _ = client
    do_login(client)
    return c.post("/api/units", json={"cid": 11})


# ---------------- V-001 Host 校验 ----------------

class TestHostGuard:
    def test_forged_host_rejected(self, client):
        c, _ = client
        r = c.get("/api/status", headers={"Host": "attacker.example"})
        assert r.status_code == 403

    def test_localhost_allowed(self, client):
        c, _ = client
        assert c.get("/api/status", headers={"Host": "localhost"}).status_code == 200

    def test_loopback_ip_allowed(self, client):
        c, _ = client
        assert c.get("/api/status", headers={"Host": "127.0.0.1:17777"}).status_code == 200

    def test_all_api_routes_guarded(self, client):
        c, _ = client
        for path in ("/api/status", "/api/login", "/api/units",
                     "/api/refresh", "/api/start", "/api/logout"):
            r = c.open(path, method="POST" if path != "/api/status" else "GET",
                       json={}, headers={"Host": "attacker.example"})
            assert r.status_code == 403, f"{path} 未受 Host 校验保护"


# ---------------- V-003 参数范围 ----------------

class TestParamRange:
    @pytest.mark.parametrize("param", ["-1", "-100", "101", "1000"])
    def test_accuracy_out_of_range_rejected(self, client, param):
        load_units(client)
        c, _ = client
        r = c.post("/api/start", json={"units": [1], "param": param})
        assert r.status_code == 400
        assert "参数格式错误" in r.get_json()["error"]

    @pytest.mark.parametrize("param", ["0", "100", "70,100", "0,0"])
    def test_accuracy_in_range_accepted(self, client, param):
        load_units(client)
        c, _ = client
        r = c.post("/api/start", json={"units": [1], "param": param})
        assert r.status_code == 200

    @pytest.mark.parametrize("param", ["-5", "86401", "999999999"])
    def test_time_out_of_range_rejected(self, client, param):
        load_units(client)
        c, _ = client
        c.post("/api/mode", json={"mode": "time"})
        r = c.post("/api/start", json={"units": [1], "param": param})
        assert r.status_code == 400

    def test_time_in_range_accepted(self, client):
        load_units(client)
        c, _ = client
        c.post("/api/mode", json={"mode": "time"})
        r = c.post("/api/start", json={"units": [1], "param": "30"})
        assert r.status_code == 200

    def test_range_lower_bound_checked(self, client):
        load_units(client)
        c, _ = client
        r = c.post("/api/start", json={"units": [1], "param": "-5,50"})
        assert r.status_code == 400


# ---------------- V-012 units=null ----------------

class TestNullUnits:
    def test_null_units_rejected_not_all_units(self, client):
        load_units(client)
        c, state = client
        r = c.post("/api/start", json={"units": None, "param": "100"})
        assert r.status_code == 400
        assert "null" in r.get_json()["error"]
        # 关键:不得退化成"全部单元"并把任务跑起来
        assert state.running is False

    def test_missing_units_still_means_all(self, client):
        """键缺失仍按原语义=全部单元(0),保持向后兼容"""
        load_units(client)
        c, _ = client
        r = c.post("/api/start", json={"param": "100"})
        assert r.status_code == 200


# ---------------- V-006 会话关闭 ----------------

class TestSessionClose:
    def test_logout_closes_session(self, client):
        load_units(client)
        c, state = client
        session = state.task.session
        assert session.closed is False
        assert c.post("/api/logout").status_code == 200
        assert session.closed is True

    def test_relogin_closes_previous_session(self, client):
        c, state = client
        do_login(client)
        first = state.task.session
        do_login(client)
        assert first.closed is True
        assert state.task.session.closed is False

    def test_login_failure_closes_its_session(self, client, monkeypatch):
        class BadTask(FakeTask):
            def login(self):
                raise web_gui.LoginError("帐号或密码错误!")

        monkeypatch.setattr(welearn_accuracy, "AccuracyTask", BadTask)
        c, _ = client
        r = do_login(client)
        assert r.status_code == 200
        assert r.get_json()["ok"] is False


# ---------------- V-004 登录独占 ----------------

class TestCredentialTypes:
    @pytest.mark.parametrize("body", [
        {"username": None, "password": None},
        {"username": 123, "password": 456},
        {"username": [], "password": {}},
    ])
    def test_non_string_credentials_rejected(self, client, body):
        c, _ = client
        r = c.post("/api/login", json=dict(body, mode="accuracy"))
        assert r.status_code == 400
        assert "字符串" in r.get_json()["error"]

    def test_null_does_not_reach_network(self, client, monkeypatch):
        """null 曾被 str() 变成 "None" 并通过空值检查,触发 5 次真实登录尝试。"""
        called = {"n": 0}

        def boom(*a, **k):
            called["n"] += 1
            raise AssertionError("不应发生登录尝试")

        monkeypatch.setattr(FakeTask, "login", boom)
        c, _ = client
        r = c.post("/api/login", json={"username": None, "password": None,
                                       "mode": "accuracy"})
        assert r.status_code == 400
        assert called["n"] == 0


class TestLoginExclusivity:
    def test_begin_login_is_atomic(self):
        state = web_gui.AppState()
        assert state.begin_login() is True
        assert state.begin_login() is False      # 第二次必须被拒
        state.end_login()
        assert state.begin_login() is True
        state.end_login()

    def test_begin_exclusive_blocks_double_fetch(self):
        state = web_gui.AppState()
        assert state.begin_exclusive("加载单元中...") is True
        assert state.begin_exclusive("加载单元中...") is False
        state.end_exclusive()
        assert state.begin_exclusive("加载单元中...") is True
        state.end_exclusive()

    def test_exclusive_blocks_while_running(self):
        state = web_gui.AppState()
        state.running = True
        assert state.begin_exclusive("x") is False
        assert state.begin_login() is False

    def test_login_flag_released_on_failure(self, client):
        c, state = client
        # 失败登录后必须释放占位,否则后续登录全部 409
        r = c.post("/api/login", json={"username": "", "password": ""})
        assert r.status_code == 400
        r2 = do_login(client)
        assert r2.status_code == 200
        assert state.login_in_progress is False
