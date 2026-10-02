"""登录门禁会话核心：装载密钥 / 签发凭据 / 校验放行 / 过期登出。

三处互相咬住的决策：

1. 密钥来源：优先读外部环境源（环境变量 AUTH_SECRET_KEY），多副本部署时
   各副本签名可互认；环境源缺失时自生成并原子落盘到 auth/secret_keys.json
   （该文件已加入 .gitignore，避免密钥进版本库扩大泄漏面）。
2. 滑动续期与绝对到期并存：滑动窗口 30 分钟、绝对上限 8 小时。
   凭据剩余有效期 = min(滑动剩余, 绝对剩余)；续期只在签名与有效期校验
   全部通过之后发生，续期不得绕开校验。
3. 密钥轮换：新密钥原子替换（临时文件 + os.replace），旧密钥保留 24 小时
   宽限期且仅用于验签，不再签发新凭据。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

# ---- 决策参数 ----
SLIDING_WINDOW_SECONDS = 30 * 60          # 滑动窗口：30 分钟无活动即过期
ABSOLUTE_EXPIRY_SECONDS = 8 * 3600        # 绝对到期：最长 8 小时，强制重登
ROTATION_GRACE_SECONDS = 24 * 3600        # 旧密钥宽限期：24 小时内仅验签
RENEW_THRESHOLD_RATIO = 0.5               # 滑动剩余不足一半时触发续期

KEY_ENV_VAR = "AUTH_SECRET_KEY"
DEFAULT_KEY_PATH = Path(__file__).with_name("secret_keys.json")
AUTH_COOKIE_NAME = "auth_token"
TOKEN_VERSION = "v1"

SOURCE_ENVIRONMENT = "environment"
SOURCE_KEY_FILE = "key-file"
SOURCE_GENERATED = "generated"

_SOURCE_LABELS = {
    SOURCE_ENVIRONMENT: "外部环境源 (env)",
    SOURCE_KEY_FILE: "本地密钥文件",
    SOURCE_GENERATED: "启动自生成落盘",
}


class KeyUnavailable(Exception):
    """密钥缺失或损坏。reason 为 'missing' 或 'corrupt'。"""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        super().__init__(detail or reason)


@dataclass
class KeyRing:
    current_kid: str
    current_secret: bytes
    source: str
    previous_kid: str | None = None
    previous_secret: bytes | None = None
    previous_grace_until: float = 0.0

    @property
    def source_label(self) -> str:
        return _SOURCE_LABELS.get(self.source, self.source)


@dataclass
class VerifyResult:
    status: str            # valid / valid-grace / renewed / expired / tampered
    username: str = ""
    remaining_seconds: float = 0.0
    key_used: str = ""
    new_token: str | None = None
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("valid", "valid-grace", "renewed")


# ---------------------------------------------------------------- 密钥装载

def _atomic_write_json(path: Path, data: dict) -> None:
    """原子替换：先写临时文件再 os.replace，轮换中途崩溃不留半个文件。"""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_key_file(path: Path) -> dict:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise KeyUnavailable("missing", f"密钥文件不存在: {path}")
    try:
        data = json.loads(raw)
        current = data["current"]
        secret = bytes.fromhex(current["secret"])
        if not current.get("kid") or len(secret) < 16:
            raise ValueError("key material too short")
        return data
    except (ValueError, KeyError, TypeError) as exc:
        raise KeyUnavailable("corrupt", f"密钥文件损坏: {path} ({exc})")


def _keyring_from_file(data: dict, source: str) -> KeyRing:
    current = data["current"]
    previous = data.get("previous") or {}
    ring = KeyRing(
        current_kid=current["kid"],
        current_secret=bytes.fromhex(current["secret"]),
        source=source,
    )
    if previous.get("kid") and previous.get("secret"):
        ring.previous_kid = previous["kid"]
        ring.previous_secret = bytes.fromhex(previous["secret"])
        ring.previous_grace_until = float(previous.get("grace_until", 0.0))
    return ring


def load_keys(key_path: Path | None = None, env_var: str = KEY_ENV_VAR) -> KeyRing:
    """装载密钥：外部环境源优先（多副本互认），否则读本地落盘文件。

    缺失或损坏时抛 KeyUnavailable，由页面给出“生成密钥”入口而不是 500。
    """
    path = Path(key_path) if key_path else Path(DEFAULT_KEY_PATH)
    env_secret = os.environ.get(env_var, "").strip()
    if env_secret:
        try:
            secret = bytes.fromhex(env_secret)
        except ValueError:
            secret = hashlib.sha256(env_secret.encode("utf-8")).digest()
        ring = KeyRing(
            current_kid=hashlib.sha256(secret).hexdigest()[:12],
            current_secret=secret,
            source=SOURCE_ENVIRONMENT,
        )
        try:  # 外部源为主时，仍捡起文件里的旧密钥用于宽限验签
            file_ring = _keyring_from_file(_read_key_file(path), SOURCE_KEY_FILE)
            if file_ring.previous_kid:
                ring.previous_kid = file_ring.previous_kid
                ring.previous_secret = file_ring.previous_secret
                ring.previous_grace_until = file_ring.previous_grace_until
        except KeyUnavailable:
            pass
        return ring
    return _keyring_from_file(_read_key_file(path), SOURCE_KEY_FILE)


def generate_keys(key_path: Path | None = None) -> KeyRing:
    """自生成密钥并原子落盘（密钥缺失/损坏时页面上的生成入口）。"""
    path = Path(key_path) if key_path else Path(DEFAULT_KEY_PATH)
    secret = secrets.token_bytes(32)
    data = {"current": {
        "kid": secrets.token_hex(6),
        "secret": secret.hex(),
        "created_at": time.time(),
    }}
    _atomic_write_json(path, data)
    ring = _keyring_from_file(data, SOURCE_GENERATED)
    return ring


def rotate_keys(key_path: Path | None = None, now: float | None = None) -> KeyRing:
    """轮换：原子替换密钥文件，旧密钥留 24 小时宽限期仅用于验签。"""
    now = time.time() if now is None else now
    path = Path(key_path) if key_path else Path(DEFAULT_KEY_PATH)
    old = _keyring_from_file(_read_key_file(path), SOURCE_KEY_FILE)
    secret = secrets.token_bytes(32)
    data = {
        "current": {
            "kid": secrets.token_hex(6),
            "secret": secret.hex(),
            "created_at": now,
        },
        "previous": {
            "kid": old.current_kid,
            "secret": old.current_secret.hex(),
            "grace_until": now + ROTATION_GRACE_SECONDS,
        },
    }
    _atomic_write_json(path, data)
    return _keyring_from_file(data, SOURCE_KEY_FILE)


# ---------------------------------------------------------------- 签发凭据

def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _sign(secret: bytes, signing_input: str) -> str:
    return _b64e(hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest())


def issue_credential(keyring: KeyRing, username: str, now: float | None = None,
                     orig_iat: float | None = None) -> str:
    """签发凭据：滑动窗口 + 绝对到期两个时钟同时写进令牌。"""
    now = time.time() if now is None else now
    orig = now if orig_iat is None else orig_iat
    payload = {
        "sub": username,
        "iat": now,
        "orig_iat": orig,
        "exp": now + SLIDING_WINDOW_SECONDS,
        "abs_exp": orig + ABSOLUTE_EXPIRY_SECONDS,
    }
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{TOKEN_VERSION}.{keyring.current_kid}.{body}"
    return f"{signing_input}.{_sign(keyring.current_secret, signing_input)}"


# ---------------------------------------------------------------- 校验放行

def verify_credential(keyring: KeyRing, token: str, now: float | None = None) -> VerifyResult:
    """校验放行：验签 -> 绝对到期 -> 滑动窗口 -> （通过后）按需滑动续期。

    cookie 被篡改直接拒绝（tampered），不续期；旧密钥在 24 小时宽限期内
    仅用于验签（valid-grace），续期一律改用当前密钥签发。
    """
    now = time.time() if now is None else now
    try:
        version, kid, body, sig = token.split(".")
        if version != TOKEN_VERSION:
            raise ValueError("bad version")
        payload = json.loads(_b64d(body))
        username = str(payload["sub"])
        exp = float(payload["exp"])
        abs_exp = float(payload["abs_exp"])
        orig_iat = float(payload["orig_iat"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return VerifyResult("tampered", reason="凭据格式非法，直接拒绝")

    signing_input = f"{version}.{kid}.{body}"
    if hmac.compare_digest(sig, _sign(keyring.current_secret, signing_input)):
        key_used = "当前密钥"
        grace = False
    elif (keyring.previous_secret and kid == keyring.previous_kid
          and now <= keyring.previous_grace_until
          and hmac.compare_digest(sig, _sign(keyring.previous_secret, signing_input))):
        key_used = "旧密钥（宽限期验签）"
        grace = True
    else:
        return VerifyResult("tampered", reason="签名不匹配（cookie 被篡改），直接拒绝")

    if now > abs_exp:
        return VerifyResult("expired", username=username, key_used=key_used,
                            reason="超过绝对到期上限，强制重新登录")
    if now > exp:
        return VerifyResult("expired", username=username, key_used=key_used,
                            reason="滑动窗口内无活动，会话过期")

    remaining = min(exp, abs_exp) - now
    sliding_remaining = exp - now
    if sliding_remaining <= SLIDING_WINDOW_SECONDS * RENEW_THRESHOLD_RATIO:
        # 续期发生在全部校验通过之后；绝对到期时钟沿用 orig_iat 不重置
        new_token = issue_credential(keyring, username, now=now, orig_iat=orig_iat)
        return VerifyResult("renewed", username=username,
                            remaining_seconds=remaining, key_used=key_used,
                            new_token=new_token, reason="滑动续期：剩余窗口过半已消耗")
    return VerifyResult("valid-grace" if grace else "valid", username=username,
                        remaining_seconds=remaining, key_used=key_used)


# ---------------------------------------------------------------- 过期登出

def logout_expired(response, cookie_name: str = AUTH_COOKIE_NAME):
    """过期登出：清除凭据 cookie，返回同一个 response 便于链式使用。"""
    response.delete_cookie(cookie_name)
    return response


# ---------------------------------------------------------------- 展示辅助

def format_remaining(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"
