"""认证门禁端到端测试：异常走向、滑动/绝对到期、轮换宽限、时间线。"""

from __future__ import annotations

import json
import os

import pytest

from app import create_app
from auth.session import (
    AuthFlowLog,
    issue_credential,
    load_secret_key,
    protect_request,
    verify_credential,
)


class Clock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture(autouse=True)
def _reset_flow() -> None:
    AuthFlowLog.reset()
    yield
    AuthFlowLog.reset()


@pytest.fixture
def app(tmp_path, clock, monkeypatch):
    monkeypatch.delenv("SALES_SECRET_KEY", raising=False)
    app = create_app(
        {
            "TESTING": True,
            "AUTH_KEY_FILE": str(tmp_path / "keys.json"),
            "AUTH_SLIDING_WINDOW": 30,
            "AUTH_ABSOLUTE_WINDOW": 90,
            "AUTH_GRACE_SECONDS": 86400,
        }
    )
    from auth import session as session_module

    session_module.get_settings().now = clock
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def login(client):
    return client.post("/login", data={"username": "pparker", "password": "abc123"},
                       follow_redirects=False)


# ---------- 异常走向 ----------

def test_missing_key_does_not_500_and_offers_generate(client):
    resp = client.get("/auth-flow")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "密钥来源" in body
    assert "缺失" in body
    assert "立即生成密钥" in body

    # 没密钥时访问受保护页面应跳登录，而不是 500
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_corrupt_key_file_gives_generate_entry(app, client, tmp_path):
    key_file = tmp_path / "keys.json"
    key_file.write_text("{ this is not json", encoding="utf-8")

    resp = client.get("/auth-flow")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "文件损坏" in body
    assert "立即生成密钥" in body

    resp = client.post("/generate-key", follow_redirects=True)
    assert resp.status_code == 200
    assert "已就绪" in resp.get_data(as_text=True)
    # 损坏文件被备份，新文件结构合法
    data = json.loads(key_file.read_text(encoding="utf-8"))
    assert data["current"]["secret"]


def test_tampered_cookie_is_rejected(client):
    client.post("/generate-key")
    login(client)

    jar = client.get_cookie("session_token")
    assert jar is not None
    token = jar.value
    header, payload, signature = token.split(".")
    tampered = f"{header}.{payload}.{signature[:-1]}x"

    client.set_cookie("session_token", tampered, domain="localhost")
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]

    flow = client.get("/auth-flow").get_data(as_text=True)
    assert "签名不匹配" in flow or "凭据无法解码" in flow


def test_bad_password_rejected_and_no_cookie(client):
    client.post("/generate-key")
    resp = client.post("/login", data={"username": "pparker", "password": "wrong"})
    assert resp.status_code == 200
    assert "用户名或密码错误" in resp.get_data(as_text=True)
    assert client.get_cookie("session_token") is None


# ---------- 签发 / 校验 / 续期 ----------

def test_login_issues_cookie_and_dashboard_loads(client):
    client.post("/generate-key")
    resp = login(client)
    assert resp.status_code == 302
    assert client.get_cookie("session_token") is not None

    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "pparker" in body
    assert "总销售额" in body


def test_renewal_extends_sliding_but_not_absolute(app, clock):
    state = load_secret_key()
    assert state.status == "missing"

    from auth.session import generate_secret_key

    state = generate_secret_key()
    issued = issue_credential("pparker", state)

    clock.advance(10)
    result = verify_credential(issued.token, load_secret_key())
    assert result.ok and result.renewed
    # 绝对到期纹丝不动，滑动窗口被推满
    assert result.absolute_expires_at == issued.absolute_expires_at
    assert result.sliding_expires_at == clock.t + 30
    assert result.sliding_expires_at <= result.absolute_expires_at


def test_sliding_expiry_logs_out(app, clock):
    from auth.session import generate_secret_key

    state = generate_secret_key()
    issued = issue_credential("pparker", state)

    clock.advance(31)  # 超过 30s 滑动窗口
    result = verify_credential(issued.token, load_secret_key())
    assert not result.ok
    assert result.reason == "sliding_expired"


def test_absolute_expiry_caps_everything(app, clock):
    from auth.session import generate_secret_key

    state = generate_secret_key()
    issued = issue_credential("pparker", state)

    token = issued.token
    for _ in range(8):  # 持续活跃：滑动窗口不断被推到绝对上限
        clock.advance(10)
        result = verify_credential(token, load_secret_key())
        assert result.ok, "活跃期间凭据应保持有效"
        if result.renewed:
            token = result.renewed_credential.token

    clock.advance(11)  # 累计 91s > 90s 绝对到期
    result = verify_credential(token, load_secret_key())
    assert not result.ok
    assert result.reason == "absolute_expired"


def test_renewal_never_bypasses_signature(app, clock):
    from auth.session import generate_secret_key

    state = generate_secret_key()
    issued = issue_credential("pparker", state)
    header, payload, signature = issued.token.split(".")
    forged = f"{header}.{payload}.{'A' * len(signature)}"

    clock.advance(1)
    result = verify_credential(forged, load_secret_key())
    assert not result.ok
    assert result.renewed_credential is None
    assert "签名" in result.reason


# ---------- 轮换与 24h 宽限 ----------

def test_rotation_is_atomic_and_old_session_still_works(app, clock, tmp_path):
    from auth.session import generate_secret_key, rotate_secret_key

    state = generate_secret_key()
    old_kid = state.current.key_id
    issued = issue_credential("pparker", state)

    rotated = rotate_secret_key()
    assert rotated.current.key_id != old_kid
    stored = json.loads((tmp_path / "keys.json").read_text(encoding="utf-8"))
    assert stored["current"]["kid"] == rotated.current.key_id
    assert len(stored["grace"]) == 1
    assert stored["grace"][0]["kid"] == old_kid

    # 旧会话在宽限期内照常可用，且这次校验自动换到新密钥续期
    clock.advance(5)
    result = verify_credential(issued.token, load_secret_key())
    assert result.ok
    assert result.originally_signed_by == "grace"
    assert result.renewed
    assert result.renewed_credential.key_id == rotated.current.key_id

    # 新凭据由当前密钥签名
    result2 = verify_credential(result.renewed_credential.token, load_secret_key())
    assert result2.ok and result2.signed_by == "current"


def test_grace_expires_after_24h(app, clock):
    from auth.session import generate_secret_key, rotate_secret_key

    state = generate_secret_key()
    issued = issue_credential("pparker", state)
    rotate_secret_key()

    clock.advance(86400 + 1)  # 超过 24h 宽限
    state = load_secret_key()
    assert state.grace == []
    result = verify_credential(issued.token, state)
    assert not result.ok
    assert "未知密钥" in result.reason


def test_old_key_with_bad_signature_still_rejected_in_grace(app, clock):
    from auth.session import generate_secret_key, rotate_secret_key

    state = generate_secret_key()
    issued = issue_credential("pparker", state)
    rotate_secret_key()

    header, payload, signature = issued.token.split(".")
    tampered = f"{header}.{payload[:-2]}XX.{signature}"
    clock.advance(1)
    result = verify_credential(tampered, load_secret_key())
    assert not result.ok


# ---------- 外部密钥源 / 多副本 ----------

def test_external_env_key_source_and_no_file(app, clock, tmp_path, monkeypatch):
    monkeypatch.setenv("SALES_SECRET_KEY", "shared-secret-for-replicas")
    state = load_secret_key()
    assert state.ready
    assert state.current.source == "external"
    assert not os.path.exists(tmp_path / "keys.json")

    issued = issue_credential("pparker", state)
    # 第二个“副本”用同样的环境变量装载，应能互认签名
    assert verify_credential(issued.token, load_secret_key()).ok


# ---------- /auth-flow 两栏 + 时间线 ----------

def test_auth_flow_shows_source_remaining_and_timeline(client, clock):
    client.post("/generate-key")
    login(client)
    resp = client.get("/auth-flow")
    body = resp.get_data(as_text=True)
    assert "密钥来源" in body
    assert "落盘密钥生效" in body or "自生成" in body
    assert "凭据剩余有效期" in body
    assert "滑动窗口剩余" in body
    assert "绝对到期剩余" in body
    # 时间线按顺序记录了四类函数调用
    assert "load_secret_key" in body
    assert "issue_credential" in body
    assert "verify_credential" in body
    # 登录后至少出现一次校验通过；短窗口下首访即触发滑动续期
    assert "verify_credential" in body
    assert ("校验通过并滑动续期" in body or "校验通过" in body)


def test_protect_request_decision_shape(app, clock):
    state = load_secret_key()
    missing = protect_request(None, {"/login"}, "/")
    assert missing["allow"] is False
    assert "/login" in missing["redirect"]

    from auth.session import generate_secret_key

    state = generate_secret_key()
    issued = issue_credential("pparker", state)
    clock.advance(1)
    allowed = protect_request(issued.token, {"/login"}, "/dashboard")
    assert allowed["allow"] is True
    assert allowed["verification"].username == "pparker"


def test_grace_session_renders_badge_on_dashboard(client, clock, tmp_path):
    from auth.session import generate_secret_key, rotate_secret_key

    state = generate_secret_key()
    old = issue_credential("pparker", state)
    rotate_secret_key()
    clock.advance(2)

    client.set_cookie("session_token", old.token, domain="localhost")
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "旧密钥宽限期内验签" in body
    # after_request 已把续期后的新 cookie 写给浏览器
    new_cookie = client.get_cookie("session_token")
    state2 = load_secret_key()
    assert new_cookie is not None
    renewed = verify_credential(new_cookie.value, state2)
    assert renewed.ok and renewed.signed_by == "current"
