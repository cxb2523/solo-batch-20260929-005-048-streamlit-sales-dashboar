"""登录门禁四函数 + /auth-flow 页面的行为测试。"""
import json
import time

import pytest

from auth import session as auth


@pytest.fixture()
def key_path(tmp_path, monkeypatch):
    """隔离密钥落盘位置，并确保不读外部环境源。"""
    monkeypatch.delenv(auth.KEY_ENV_VAR, raising=False)
    path = tmp_path / "secret_keys.json"
    monkeypatch.setattr(auth, "DEFAULT_KEY_PATH", path)
    return path


@pytest.fixture()
def keyring(key_path):
    return auth.generate_keys(key_path)


T0 = 1_700_000_000.0


# ------------------------------------------------------------ 装载密钥

def test_load_keys_prefers_external_env_source(key_path, monkeypatch):
    monkeypatch.setenv(auth.KEY_ENV_VAR, "feedface" * 8)
    ring = auth.load_keys()
    assert ring.source == auth.SOURCE_ENVIRONMENT
    assert ring.current_secret == bytes.fromhex("feedface" * 8)


def test_load_keys_missing_raises_and_generate_persists(key_path):
    with pytest.raises(auth.KeyUnavailable) as exc:
        auth.load_keys()
    assert exc.value.reason == "missing"
    ring = auth.generate_keys(key_path)
    assert ring.source == auth.SOURCE_GENERATED
    assert key_path.exists()
    assert auth.load_keys().current_kid == ring.current_kid


def test_load_keys_corrupt_file_raises(key_path):
    key_path.write_text("{not json", encoding="utf-8")
    with pytest.raises(auth.KeyUnavailable) as exc:
        auth.load_keys()
    assert exc.value.reason == "corrupt"


def test_env_source_enables_multi_replica_interop(key_path, monkeypatch):
    """同一外部密钥 => 两个副本各自装载的 keyring 可互相验签。"""
    monkeypatch.setenv(auth.KEY_ENV_VAR, "shared-secret")
    replica_a = auth.load_keys()
    replica_b = auth.load_keys()
    token = auth.issue_credential(replica_a, "pparker", now=T0)
    assert auth.verify_credential(replica_b, token, now=T0).status == "valid"


# ------------------------------------------------------------ 签发 / 校验

def test_issue_and_verify_roundtrip(keyring):
    token = auth.issue_credential(keyring, "pparker", now=T0)
    result = auth.verify_credential(keyring, token, now=T0 + 60)
    assert result.status == "valid"
    assert result.username == "pparker"
    assert 0 < result.remaining_seconds <= auth.SLIDING_WINDOW_SECONDS - 60


def test_tampered_cookie_rejected_without_renewal(keyring):
    token = auth.issue_credential(keyring, "pparker", now=T0)
    body = token.split(".")[2]
    forged_body = auth._b64e(json.dumps({
        "sub": "admin", "iat": T0, "orig_iat": T0,
        "exp": T0 + 10 ** 7, "abs_exp": T0 + 10 ** 7,
    }).encode())
    forged = token.replace(body, forged_body)
    result = auth.verify_credential(keyring, forged, now=T0)
    assert result.status == "tampered"
    assert result.new_token is None
    assert not result.ok


def test_garbage_cookie_rejected(keyring):
    assert auth.verify_credential(keyring, "not-a-token", now=T0).status == "tampered"


# ------------------------------------------------------------ 滑动 + 绝对双时钟

def test_sliding_renewal_after_half_window(keyring):
    token = auth.issue_credential(keyring, "pparker", now=T0)
    later = T0 + auth.SLIDING_WINDOW_SECONDS * 0.75
    result = auth.verify_credential(keyring, token, now=later)
    assert result.status == "renewed"
    assert result.new_token and result.new_token != token
    renewed = auth.verify_credential(keyring, result.new_token, now=later)
    assert renewed.status == "valid"
    # 绝对到期时钟不随续期重置
    payload = json.loads(auth._b64d(result.new_token.split(".")[2]))
    assert payload["orig_iat"] == T0
    assert payload["abs_exp"] == T0 + auth.ABSOLUTE_EXPIRY_SECONDS


def test_no_renewal_early_in_window(keyring):
    token = auth.issue_credential(keyring, "pparker", now=T0)
    result = auth.verify_credential(keyring, token, now=T0 + 60)
    assert result.status == "valid"
    assert result.new_token is None


def test_absolute_expiry_wins_over_sliding(keyring):
    """滑动窗口还新鲜，但绝对上限先到：强制登出，续期不得绕开。"""
    near_end = T0 + auth.ABSOLUTE_EXPIRY_SECONDS - 10
    token = auth.issue_credential(keyring, "pparker", now=near_end - 60, orig_iat=T0)
    payload = json.loads(auth._b64d(token.split(".")[2]))
    assert payload["exp"] > payload["abs_exp"]  # 滑动窗口被绝对上限截断
    result = auth.verify_credential(keyring, token, now=near_end)
    assert result.ok
    assert result.remaining_seconds == pytest.approx(10, abs=1)
    final = auth.verify_credential(
        keyring, token, now=T0 + auth.ABSOLUTE_EXPIRY_SECONDS + 1)
    assert final.status == "expired"
    assert final.new_token is None


def test_remaining_is_min_of_sliding_and_absolute(keyring):
    token = auth.issue_credential(
        keyring, "pparker", now=T0 + auth.ABSOLUTE_EXPIRY_SECONDS - 160, orig_iat=T0)
    result = auth.verify_credential(
        keyring, token, now=T0 + auth.ABSOLUTE_EXPIRY_SECONDS - 100)
    assert result.status == "valid"
    assert result.remaining_seconds == pytest.approx(100, abs=1)


# ------------------------------------------------------------ 轮换与宽限

def test_rotation_grace_verifies_old_tokens(key_path):
    old_ring = auth.generate_keys(key_path)
    old_token = auth.issue_credential(old_ring, "pparker", now=T0)
    new_ring = auth.rotate_keys(key_path, now=T0 + 100)
    assert new_ring.current_kid != old_ring.current_kid
    # 宽限期内旧会话仍可用（仅验签）
    result = auth.verify_credential(new_ring, old_token, now=T0 + 200)
    assert result.status == "valid-grace"
    assert "宽限" in result.key_used
    # 新凭据一律用新密钥签发
    new_token = auth.issue_credential(new_ring, "rmiller", now=T0 + 200)
    assert new_token.split(".")[1] == new_ring.current_kid


def test_rotation_grace_expires_after_24h(key_path):
    old_ring = auth.generate_keys(key_path)
    old_token = auth.issue_credential(old_ring, "pparker", now=T0)
    new_ring = auth.rotate_keys(key_path, now=T0)
    result = auth.verify_credential(
        new_ring, old_token, now=T0 + auth.ROTATION_GRACE_SECONDS + 1)
    assert result.status == "tampered"  # 宽限期外旧密钥不再验签


def test_rotation_is_atomic_replace(key_path):
    auth.generate_keys(key_path)
    auth.rotate_keys(key_path, now=T0)
    leftovers = [p for p in key_path.parent.iterdir() if p.suffix == ".tmp"]
    assert leftovers == []
    data = json.loads(key_path.read_text(encoding="utf-8"))
    assert set(data) == {"current", "previous"}


def test_renewal_never_bypasses_validation(keyring):
    """过期凭据不得借续期复活。"""
    token = auth.issue_credential(keyring, "pparker", now=T0)
    expired = auth.verify_credential(
        keyring, token, now=T0 + auth.SLIDING_WINDOW_SECONDS + 1)
    assert expired.status == "expired"
    assert expired.new_token is None


# ------------------------------------------------------------ 过期登出

def test_logout_expired_clears_cookie():
    from flask import Flask, make_response
    app = Flask(__name__)
    with app.test_request_context():
        resp = make_response("bye")
        auth.logout_expired(resp)
        cookie = resp.headers.get("Set-Cookie", "")
        assert auth.AUTH_COOKIE_NAME in cookie
        assert "Expires" in cookie or "expires" in cookie


# ------------------------------------------------------------ Flask 集成

@pytest.fixture()
def client(key_path):
    auth.generate_keys(key_path)
    import app as flask_app
    flask_app.app.config.update(TESTING=True)
    return flask_app.app.test_client()


def test_protected_route_redirects_when_anonymous(client):
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_login_sets_credential_and_passes_gate(client):
    resp = client.post("/login", data={"username": "pparker", "password": "sales123"})
    assert resp.status_code == 302
    assert auth.AUTH_COOKIE_NAME in resp.headers.get("Set-Cookie", "")
    assert client.get("/").status_code == 200


def test_tampered_cookie_redirects_and_clears(client):
    client.set_cookie(auth.AUTH_COOKIE_NAME, "v1.bad.body.sig")
    resp = client.get("/")
    assert resp.status_code == 302
    cleared = resp.headers.get("Set-Cookie", "")
    assert auth.AUTH_COOKIE_NAME in cleared  # 过期登出：清除 cookie


def test_auth_flow_page_shows_source_and_remaining_columns(client):
    client.post("/login", data={"username": "pparker", "password": "sales123"})
    resp = client.get("/auth-flow")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "密钥来源" in html
    assert "凭据剩余有效期" in html
    assert "load_keys()" in html and "verify_credential()" in html
    assert "本地密钥文件" in html or "启动自生成落盘" in html


def test_auth_flow_offers_generation_when_key_missing(client, key_path):
    key_path.unlink()  # 运行期密钥被删：页面给生成入口而不是 500
    resp = client.get("/auth-flow")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "生成密钥" in html
    resp = client.post("/auth-flow/generate-key")
    assert resp.status_code == 302
    assert key_path.exists()
    assert "load_keys()" in client.get("/auth-flow").get_data(as_text=True)


def test_auth_flow_replay_after_rotation_shows_grace(client, key_path):
    client.post("/login", data={"username": "pparker", "password": "sales123"})
    client.post("/auth-flow/rotate-key")
    html = client.get("/auth-flow").get_data(as_text=True)
    assert "valid-grace" in html
    assert "宽限" in html
