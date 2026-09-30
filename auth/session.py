"""会话认证核心。

登录门禁原先直接写在 ``app.py`` 的 ``before_request`` 里，这里拆成四个
可独立调用的函数：

1. :func:`load_secret_key`   —— 装载密钥（外部环境变量优先，其次落盘文件）；
2. :func:`issue_credential`  —— 签发凭据（HMAC 签名 cookie，含滑动+绝对到期）；
3. :func:`verify_credential` —— 校验放行（验签 -> 验过期 -> 滑动续期）；
4. :func:`end_session`       —— 过期登出（清理凭据并记录）。

另有 :func:`protect_request` 作为 ``before_request`` 的薄封装，密钥轮换
``rotate_secret_key`` / ``generate_secret_key`` 走原子替换并保留旧密钥 24h 宽限。
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
from dataclasses import dataclass, field
from threading import Lock
from typing import Any
from urllib.parse import quote

SLIDING_WINDOW_DEFAULT = 30 * 60          # 滑动续期窗口：30 分钟不活跃即失效
ABSOLUTE_WINDOW_DEFAULT = 12 * 60 * 60    # 绝对到期：无论是否活跃最多 12 小时
GRACE_SECONDS_DEFAULT = 24 * 60 * 60      # 轮换后旧密钥验签宽限：24 小时
COOKIE_NAME_DEFAULT = "session_token"
KEY_FILE_DEFAULT = "instance/secret_keys.json"
MAX_FLOW_EVENTS = 200


class _SilentFlowLog:
    """内部辅助：不进时间线的空日志（轮换内部装载不产生噪音事件）。"""

    def record(self, function: str, outcome: str, **detail):
        return {"function": function, "outcome": outcome, "detail": detail}

    def events(self):
        return []

    @staticmethod
    def reset():
        return None

SIGNING_ALGORITHM = "HS256"


@dataclass
class AuthSettings:
    """认证相关配置，``init_app`` 时由 Flask config / 环境变量覆盖。"""

    key_env_var: str = "SALES_SECRET_KEY"
    key_file: str = KEY_FILE_DEFAULT
    cookie_name: str = COOKIE_NAME_DEFAULT
    cookie_secure: bool = False
    sliding_window: int = SLIDING_WINDOW_DEFAULT
    absolute_window: int = ABSOLUTE_WINDOW_DEFAULT
    grace_seconds: int = GRACE_SECONDS_DEFAULT
    auto_generate_key: bool = False
    now: Any = time.time


_SETTINGS = AuthSettings()


def get_settings() -> AuthSettings:
    """返回当前进程内生效的配置单例。"""

    return _SETTINGS


class AuthFlowLog:
    """进程内时间线：按时间顺序记录每次认证函数调用。

    供 ``/auth-flow`` 页面回放；测试用 :meth:`reset` 清空。
    """

    _instance: "AuthFlowLog | None" = None
    _instance_lock = Lock()

    def __init__(self, max_events: int = MAX_FLOW_EVENTS) -> None:
        self._events: list[dict[str, Any]] = []
        self._lock = Lock()
        self._seq = 0
        self._max_events = max_events

    @classmethod
    def instance(cls) -> "AuthFlowLog":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        with cls._instance_lock:
            cls._instance = cls()

    def record(self, function: str, outcome: str, **detail: Any) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            event = {
                "seq": self._seq,
                "ts": detail.pop("_now", None),
                "function": function,
                "outcome": outcome,
                "detail": detail,
            }
            self._events.append(event)
            if len(self._events) > self._max_events:
                del self._events[: len(self._events) - self._max_events]
        return event

    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(reversed(self._events))


@dataclass
class LoadedKey:
    key_id: str
    secret: str
    loaded_at: float
    source: str            # "external" | "generated"
    retired_at: float | None = None

    def as_record(self) -> dict[str, Any]:
        rec = {
            "kid": self.key_id,
            "secret": self.secret,
            "loaded_at": self.loaded_at,
            "source": self.source,
        }
        if self.retired_at is not None:
            rec["retired_at"] = self.retired_at
        return rec


@dataclass
class KeyState:
    """密钥装载结果。``status`` 取值见 :func:`load_secret_key`。"""

    status: str
    current: LoadedKey | None = None
    grace: list[LoadedKey] = field(default_factory=list)
    detail: str = ""

    @property
    def ready(self) -> bool:
        return self.status == "ready" and self.current is not None

    @property
    def key_source(self) -> str:
        if self.current is not None:
            return "外部环境变量" if self.current.source == "external" else "启动自生成（落盘）"
        if self.status == "corrupt":
            return "落盘文件损坏"
        return "缺失（尚未生成）"

    def grace_rows(self) -> list[dict[str, Any]]:
        rows = []
        for key in self.grace:
            rows.append(
                {
                    "kid": key.key_id,
                    "retired_at": key.retired_at,
                    "remaining": None
                    if key.retired_at is None
                    else max(0, int(get_settings().grace_seconds - (get_settings().now() - key.retired_at))),
                }
            )
        return rows


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _derive_kid(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]


def _atomic_write_json(path: str, payload: dict[str, Any]) -> None:
    """先写临时文件再 ``os.replace``，保证密钥轮换是原子替换。"""

    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".keyrotate-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _read_key_file(path: str) -> dict[str, Any] | None:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or not isinstance(data.get("current"), dict):
        raise ValueError("key store missing current key")
    return data


def _new_secret() -> str:
    return secrets.token_urlsafe(48)


def _state_from_external(secret: str, now: float) -> KeyState:
    current = LoadedKey(
        key_id=_derive_kid(secret),
        secret=secret,
        loaded_at=now,
        source="external",
    )
    return KeyState(status="ready", current=current, grace=[], detail=get_settings().key_env_var)


def _state_from_file(data: dict[str, Any], now: float) -> KeyState:
    raw = data["current"]
    current = LoadedKey(
        key_id=str(raw["kid"]),
        secret=str(raw["secret"]),
        loaded_at=float(raw.get("loaded_at", now)),
        source="generated",
    )
    grace: list[LoadedKey] = []
    for old in data.get("grace", []):
        retired_at = float(old.get("retired_at", 0))
        if now - retired_at < get_settings().grace_seconds:
            grace.append(
                LoadedKey(
                    key_id=str(old["kid"]),
                    secret=str(old["secret"]),
                    loaded_at=float(old.get("loaded_at", retired_at)),
                    source="generated",
                    retired_at=retired_at,
                )
            )
    return KeyState(status="ready", current=current, grace=grace, detail=get_settings().key_file)


def load_secret_key(
    settings: AuthSettings | None = None,
    log: AuthFlowLog | None = None,
) -> KeyState:
    """装载当前签名密钥与宽限期内的旧密钥。

    外部环境变量优先（多副本共享同一密钥，签名可互认；密钥不落版本库）；
    没有外部源时读取落盘文件。文件缺失返回 ``missing``、内容损坏返回
    ``corrupt``，由页面给出“立即生成”入口，而不是抛 500。
    """

    cfg = settings or _SETTINGS
    flow = log or AuthFlowLog.instance()
    now = cfg.now()
    env_secret = os.environ.get(cfg.key_env_var, "").strip()
    if env_secret:
        state = _state_from_external(env_secret, now)
        flow.record("load_secret_key", "外部密钥生效", source="external", kid=state.current.key_id)
        return state

    try:
        data = _read_key_file(cfg.key_file)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        state = KeyState(status="corrupt", detail=f"{type(exc).__name__}: {exc}")
        flow.record(
            "load_secret_key",
            "落盘密钥损坏",
            source="corrupt",
            error=str(exc),
            _now=now,
        )
        return state

    if data is None:
        if cfg.auto_generate_key:
            state = _persist_generated_key(cfg, now)
            flow.record(
                "load_secret_key",
                "首次启动自生成并落盘",
                source="generated",
                kid=state.current.key_id,
                _now=now,
            )
            return state
        state = KeyState(status="missing", detail=cfg.key_file)
        flow.record("load_secret_key", "密钥缺失，等待生成", source="missing", _now=now)
        return state

    state = _state_from_file(data, now)
    flow.record(
        "load_secret_key",
        "落盘密钥生效",
        source="generated",
        kid=state.current.key_id,
        grace=len(state.grace),
        _now=now,
    )
    return state


def _persist_generated_key(cfg: AuthSettings, now: float) -> KeyState:
    secret = _new_secret()
    current = LoadedKey(
        key_id=_derive_kid(secret),
        secret=secret,
        loaded_at=now,
        source="generated",
    )
    _atomic_write_json(cfg.key_file, {"current": current.as_record(), "grace": []})
    return KeyState(status="ready", current=current, grace=[], detail=cfg.key_file)


def generate_secret_key(
    settings: AuthSettings | None = None,
    log: AuthFlowLog | None = None,
) -> KeyState:
    """密钥缺失/损坏时的“生成入口”：自生成密钥并原子落盘。

    若外部环境变量已配置，则无需生成；若落盘里已有可解析的密钥则幂等返回，
    避免意外轮换使在线会话失效。损坏文件先备份再覆盖。
    """

    cfg = settings or _SETTINGS
    flow = log or AuthFlowLog.instance()
    now = cfg.now()

    env_secret = os.environ.get(cfg.key_env_var, "").strip()
    if env_secret:
        flow.record("generate_secret_key", "外部源已提供，跳过生成", source="external", _now=now)
        return _state_from_external(env_secret, now)

    try:
        data = _read_key_file(cfg.key_file)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        if os.path.exists(cfg.key_file):
            backup = f"{cfg.key_file}.corrupt.{int(now)}"
            os.replace(cfg.key_file, backup)
        state = _persist_generated_key(cfg, now)
        flow.record(
            "generate_secret_key",
            "损坏密钥已备份并重新生成",
            source="generated",
            kid=state.current.key_id,
            error=str(exc),
            _now=now,
        )
        return state

    if data is not None:
        state = _state_from_file(data, now)
        flow.record("generate_secret_key", "密钥已存在，幂等返回", source="generated",
                    kid=state.current.key_id, _now=now)
        return state

    state = _persist_generated_key(cfg, now)
    flow.record("generate_secret_key", "生成入口已生成并落盘", source="generated",
                kid=state.current.key_id, _now=now)
    return state


def rotate_secret_key(
    settings: AuthSettings | None = None,
    log: AuthFlowLog | None = None,
) -> KeyState:
    """原子轮换：新密钥写入 current，旧 current 移入 grace 留 24h 验签宽限。

    外部环境变量为密钥源时（多副本共享），落盘轮换没有意义，直接返回外部
    状态；只对自生成落盘密钥执行轮换。超过宽限期的旧密钥被清除。
    """

    cfg = settings or _SETTINGS
    flow = log or AuthFlowLog.instance()
    now = cfg.now()

    env_secret = os.environ.get(cfg.key_env_var, "").strip()
    if env_secret:
        flow.record("rotate_secret_key", "外部源托管，轮换交由运维（跳过）",
                    source="external", _now=now)
        return _state_from_external(env_secret, now)

    old_state = load_secret_key(cfg, _SilentFlowLog())
    grace: list[dict[str, Any]] = []
    if old_state.ready and old_state.current is not None:
        retired = old_state.current
        retired.retired_at = now
        grace.append(retired.as_record())
    for key in old_state.grace:
        if key.retired_at is not None and now - key.retired_at < cfg.grace_seconds:
            grace.append(key.as_record())

    secret = _new_secret()
    current = LoadedKey(
        key_id=_derive_kid(secret),
        secret=secret,
        loaded_at=now,
        source="generated",
    )
    _atomic_write_json(cfg.key_file, {"current": current.as_record(), "grace": grace})
    flow.record(
        "rotate_secret_key",
        "原子替换完成，旧密钥进入宽限",
        source="generated",
        kid=current.key_id,
        grace=len(grace),
        _now=now,
    )
    grace_keys = [
        LoadedKey(
            key_id=str(g["kid"]),
            secret=str(g["secret"]),
            loaded_at=float(g.get("loaded_at", now)),
            source="generated",
            retired_at=g.get("retired_at"),
        )
        for g in grace
    ]
    return KeyState(status="ready", current=current, grace=grace_keys, detail=cfg.key_file)


@dataclass
class IssuedCredential:
    token: str
    key_id: str
    issued_at: float
    sliding_expires_at: float
    absolute_expires_at: float


@dataclass
class Verification:
    ok: bool
    reason: str = ""
    username: str | None = None
    key_id: str | None = None
    signed_by: str = ""          # current | grace
    issued_at: float | None = None
    sliding_expires_at: float | None = None
    absolute_expires_at: float | None = None
    renewed: bool = False
    renewed_credential: IssuedCredential | None = None
    originally_signed_by: str = ""

    def remaining(self, now: float) -> dict[str, int]:
        if self.sliding_expires_at is None or self.absolute_expires_at is None:
            return {"sliding": 0, "absolute": 0, "effective": 0}
        sliding = max(0, int(self.sliding_expires_at - now))
        absolute = max(0, int(self.absolute_expires_at - now))
        return {"sliding": sliding, "absolute": absolute, "effective": min(sliding, absolute)}


def _sign(secret: str, signing_input: bytes) -> str:
    return _b64url(hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest())


def _encode_token(payload: dict[str, Any], key: LoadedKey) -> str:
    header = {"alg": SIGNING_ALGORITHM, "typ": "JWT", "kid": key.key_id}
    header_b64 = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _sign(key.secret, signing_input)
    return f"{header_b64}.{payload_b64}.{signature}"


def issue_credential(
    username: str,
    state: KeyState,
    settings: AuthSettings | None = None,
    log: AuthFlowLog | None = None,
) -> IssuedCredential:
    """签发凭据：用当前密钥签名，记录滑动与绝对两个到期时间。"""

    cfg = settings or _SETTINGS
    flow = log or AuthFlowLog.instance()
    if not state.ready:
        raise RuntimeError("密钥未就绪，无法签发凭据")
    now = cfg.now()
    payload = {
        "sub": username,
        "kid": state.current.key_id,
        "iat": now,
        "sliding_exp": now + cfg.sliding_window,
        "absolute_exp": now + cfg.absolute_window,
        "jti": secrets.token_hex(8),
    }
    token = _encode_token(payload, state.current)
    credential = IssuedCredential(
        token=token,
        key_id=state.current.key_id,
        issued_at=now,
        sliding_expires_at=payload["sliding_exp"],
        absolute_expires_at=payload["absolute_exp"],
    )
    flow.record(
        "issue_credential",
        "凭据已签发",
        username=username,
        kid=state.current.key_id,
        source=state.current.source,
        sliding_ttl=cfg.sliding_window,
        absolute_ttl=cfg.absolute_window,
        _now=now,
    )
    return credential


def _decode_and_pick_key(token: str, state: KeyState) -> tuple[dict[str, Any], LoadedKey, str] | str:
    parts = token.split(".")
    if len(parts) != 3:
        return "凭据格式错误"
    header_b64, payload_b64, signature = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except (ValueError, json.JSONDecodeError):
        return "凭据无法解码"
    if header.get("alg") != SIGNING_ALGORITHM:
        return "签名算法不被接受"
    kid = header.get("kid")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    if state.current is not None and hmac.compare_digest(kid or "", state.current.key_id):
        key, signed_by = state.current, "current"
    else:
        match = next((old for old in state.grace if hmac.compare_digest(kid or "", old.key_id)), None)
        if match is None:
            return "未知密钥（可能已完成轮换宽限）"
        key, signed_by = match, "grace"
    expected = _sign(key.secret, signing_input)
    if not hmac.compare_digest(expected, signature):
        return "签名不匹配（cookie 被篡改）"
    return payload, key, signed_by


def verify_credential(
    token: str | None,
    state: KeyState,
    settings: AuthSettings | None = None,
    log: AuthFlowLog | None = None,
) -> Verification:
    """校验放行：验签 -> 查滑动/绝对到期 -> 命中滑动续期则重新签发。

    续期永远建立在“已通过完整校验”的凭据之上，绝不绕开验签；续期只把
    滑动到期向后推，绝对到期保持不变（限制凭据被窃后的最长可用时长）。
    宽限期内由旧密钥签名的会话照常放行，续期时自动换到新密钥。
    """

    cfg = settings or _SETTINGS
    flow = log or AuthFlowLog.instance()
    now = cfg.now()

    if not state.ready:
        flow.record("verify_credential", "密钥未就绪，拒绝放行", source=state.status, _now=now)
        return Verification(ok=False, reason="密钥未就绪")
    if not token:
        flow.record("verify_credential", "无凭据，需要登录", _now=now)
        return Verification(ok=False, reason="missing")

    picked = _decode_and_pick_key(token, state)
    if isinstance(picked, str):
        flow.record("verify_credential", picked, rejected=True, _now=now)
        return Verification(ok=False, reason=picked)
    payload, signing_key, signed_by = picked

    try:
        issued_at = float(payload["iat"])
        sliding_exp = float(payload["sliding_exp"])
        absolute_exp = float(payload["absolute_exp"])
        username = str(payload["sub"])
    except (KeyError, TypeError, ValueError):
        flow.record("verify_credential", "凭据字段缺失/损坏", rejected=True, _now=now)
        return Verification(ok=False, reason="凭据字段缺失/损坏")

    base = Verification(
        ok=True,
        username=username,
        key_id=signing_key.key_id,
        signed_by=signed_by,
        issued_at=issued_at,
        sliding_expires_at=sliding_exp,
        absolute_expires_at=absolute_exp,
    )

    if now >= absolute_exp:
        flow.record("verify_credential", "绝对到期，登出", username=username,
                    kid=signing_key.key_id, _now=now)
        return Verification(ok=False, reason="absolute_expired", username=username,
                            key_id=signing_key.key_id, signed_by=signed_by,
                            issued_at=issued_at, sliding_expires_at=sliding_exp,
                            absolute_expires_at=absolute_exp)
    if now >= sliding_exp:
        flow.record("verify_credential", "滑动窗口超时，登出", username=username,
                    kid=signing_key.key_id, _now=now)
        return Verification(ok=False, reason="sliding_expired", username=username,
                            key_id=signing_key.key_id, signed_by=signed_by,
                            issued_at=issued_at, sliding_expires_at=sliding_exp,
                            absolute_expires_at=absolute_exp)

    remaining = base.remaining(now)
    renewed_credential: IssuedCredential | None = None
    renewed = False
    # 滑动续期：把不活跃窗口推满，但绝不延长绝对到期
    new_sliding_exp = min(now + cfg.sliding_window, absolute_exp)
    if new_sliding_exp - sliding_exp > 0:
        renewed_payload = {
            "sub": username,
            "kid": state.current.key_id,
            "iat": issued_at,
            "sliding_exp": new_sliding_exp,
            "absolute_exp": absolute_exp,
            "jti": payload.get("jti", secrets.token_hex(8)),
        }
        new_token = _encode_token(renewed_payload, state.current)
        renewed_credential = IssuedCredential(
            token=new_token,
            key_id=state.current.key_id,
            issued_at=issued_at,
            sliding_expires_at=new_sliding_exp,
            absolute_expires_at=absolute_exp,
        )
        renewed = True

    result = Verification(
        ok=True,
        username=username,
        key_id=state.current.key_id if renewed else signing_key.key_id,
        signed_by="current" if renewed else signed_by,
        issued_at=issued_at,
        sliding_expires_at=new_sliding_exp if renewed else sliding_exp,
        absolute_expires_at=absolute_exp,
        renewed=renewed,
        renewed_credential=renewed_credential,
        originally_signed_by=signed_by,
    )
    flow.record(
        "verify_credential",
        "校验通过并滑动续期" if renewed else "校验通过",
        username=username,
        kid=result.key_id,
        signed_by=signed_by,
        renewed=renewed,
        sliding_remaining=remaining["sliding"],
        absolute_remaining=remaining["absolute"],
        _now=now,
    )
    return result


def end_session(
    reason: str = "logout",
    username: str | None = None,
    settings: AuthSettings | None = None,
    log: AuthFlowLog | None = None,
) -> dict[str, Any]:
    """过期登出：返回清除 cookie 的指令并记录登出原因。"""

    cfg = settings or _SETTINGS
    flow = log or AuthFlowLog.instance()
    flow.record(
        "end_session",
        {"logout": "主动登出", "absolute_expired": "绝对到期登出",
         "sliding_expired": "滑动超时登出", "rejected": "凭据无效登出"}.get(reason, reason),
        username=username,
        reason=reason,
        cookie=cfg.cookie_name,
        _now=cfg.now(),
    )
    return {"clear_cookie": cfg.cookie_name}


def init_app(app: Any) -> None:
    """从 Flask config / 环境变量装配配置单例。"""

    global _SETTINGS
    _SETTINGS = AuthSettings(
        key_env_var=app.config.get("AUTH_KEY_ENV_VAR", AuthSettings.key_env_var),
        key_file=app.config.get("AUTH_KEY_FILE", AuthSettings.key_file),
        cookie_name=app.config.get("AUTH_COOKIE_NAME", AuthSettings.cookie_name),
        cookie_secure=app.config.get("AUTH_COOKIE_SECURE", AuthSettings.cookie_secure),
        sliding_window=int(app.config.get("AUTH_SLIDING_WINDOW", AuthSettings.sliding_window)),
        absolute_window=int(app.config.get("AUTH_ABSOLUTE_WINDOW", AuthSettings.absolute_window)),
        grace_seconds=int(app.config.get("AUTH_GRACE_SECONDS", AuthSettings.grace_seconds)),
        auto_generate_key=bool(app.config.get("AUTH_AUTO_GENERATE_KEY", False)),
    )
    AuthFlowLog.reset()


def protect_request(
    cookie_token: str | None,
    public_paths: set[str],
    path: str,
    settings: AuthSettings | None = None,
    log: AuthFlowLog | None = None,
) -> dict[str, Any]:
    """``before_request`` 的纯函数门禁，返回给 Flask 层的处置指令。

    返回字典：
    * ``allow``            —— 是否放行；
    * ``redirect``         —— 不放行时跳转的登录地址（附带 next）；
    * ``verification``     —— 校验结果（含续期凭据）；
    * ``state``            —— 密钥状态（/auth-flow 页面复用）；
    * ``clear_cookie``     —— 失效时要求清除的 cookie 名。
    """

    cfg = settings or _SETTINGS
    flow = log or AuthFlowLog.instance()
    state = load_secret_key(cfg, flow)
    login_target = "/login?next=" + quote(path, safe="/")
    is_public = path in public_paths
    if not state.ready:
        # 公共页放行（用于展示密钥缺失入口）；受保护页跳登录，绝不抛 500
        if is_public:
            return {"allow": True, "state": state, "verification": None,
                    "redirect": None, "clear_cookie": None}
        return {"allow": False, "state": state, "verification": None,
                "redirect": login_target, "clear_cookie": None}

    # 公共页也顺手校验 cookie（不拦截），这样 /auth-flow 能显示剩余有效期；
    # 无 cookie 时 verify_credential 返回 reason=missing，不算拒绝。
    verification = verify_credential(cookie_token, state, cfg, flow)
    if verification.ok:
        return {"allow": True, "state": state, "verification": verification,
                "redirect": None, "clear_cookie": None}

    reason = verification.reason
    if reason in ("absolute_expired", "sliding_expired"):
        end_session(reason, verification.username, cfg, flow)
    elif reason not in ("missing",):
        end_session("rejected", verification.username, cfg, flow)
    if is_public:
        return {"allow": True, "state": state, "verification": verification,
                "redirect": None,
                "clear_cookie": cfg.cookie_name if cookie_token else None}
    return {"allow": False, "state": state, "verification": verification,
            "redirect": login_target,
            "clear_cookie": cfg.cookie_name if cookie_token else None}
