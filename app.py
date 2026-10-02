"""Flask 版销售看板入口。

登录门禁挂在 before_request，四个可独立调用的核心函数在 auth/session.py：
装载密钥 load_keys / 签发凭据 issue_credential / 校验放行 verify_credential /
过期登出 logout_expired。/auth-flow 页面按时间线回放每次调用。
原 Streamlit 版看板保留在 streamlit_app.py（streamlit run streamlit_app.py）。
"""
from datetime import datetime

from flask import (Flask, g, make_response, redirect, render_template,
                   request, url_for)

from auth import session as auth

app = Flask(__name__)

# 演示账号（原 Streamlit 版的两个用户）；生产应换成哈希校验
DEMO_USERS = {"pparker": "sales123", "rmiller": "sales123"}

OPEN_ENDPOINTS = {"login", "auth_flow", "auth_generate_key", "auth_rotate_key", "static"}


def _load_or_redirect():
    """密钥缺失/损坏时不抛 500，引导到 /auth-flow 的生成入口。"""
    try:
        return auth.load_keys(), None
    except auth.KeyUnavailable:
        return None, redirect(url_for("auth_flow"))


@app.before_request
def login_gate():
    if request.endpoint is None or request.endpoint in OPEN_ENDPOINTS:
        return None
    keyring, resp = _load_or_redirect()
    if keyring is None:
        return resp
    token = request.cookies.get(auth.AUTH_COOKIE_NAME)
    if not token:
        return redirect(url_for("login", next=request.path))
    result = auth.verify_credential(keyring, token)
    if result.ok:
        g.auth_result = result
        return None
    # 过期或被篡改：过期登出，清 cookie 后回登录页
    resp = make_response(redirect(url_for("login")))
    return auth.logout_expired(resp)


@app.after_request
def refresh_cookie(response):
    """滑动续期：校验通过后才换发新凭据，续期不绕开校验。"""
    result = getattr(g, "auth_result", None)
    if result is not None and result.new_token:
        response.set_cookie(auth.AUTH_COOKIE_NAME, result.new_token,
                            httponly=True, samesite="Lax")
    return response


@app.route("/")
def index():
    result = g.auth_result
    return render_template(
        "index.html",
        username=result.username,
        remaining=auth.format_remaining(result.remaining_seconds),
        key_used=result.key_used,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        keyring, resp = _load_or_redirect()
        if keyring is None:
            return resp
        if DEMO_USERS.get(username) == password:
            token = auth.issue_credential(keyring, username)
            resp = make_response(redirect(request.args.get("next") or url_for("index")))
            resp.set_cookie(auth.AUTH_COOKIE_NAME, token, httponly=True, samesite="Lax")
            return resp
        error = "用户名或密码不正确"
    return render_template("login.html", error=error, users=sorted(DEMO_USERS))


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    return auth.logout_expired(resp)


@app.route("/auth-flow")
def auth_flow():
    """按时间线回放本次请求中四个函数的调用，展示密钥来源与凭据剩余有效期。"""
    events = []

    def stamp():
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]

    def add(func, status, key_source="—", remaining="—", detail=""):
        events.append({"time": stamp(), "func": func, "status": status,
                       "key_source": key_source, "remaining": remaining,
                       "detail": detail})

    keyring = None
    try:
        keyring = auth.load_keys()
        detail = f"当前密钥 kid={keyring.current_kid}"
        if keyring.previous_kid:
            left = keyring.previous_grace_until - datetime.now().timestamp()
            detail += f"；旧密钥 kid={keyring.previous_kid} 宽限剩余 {auth.format_remaining(left)}"
        add("load_keys()", "OK", key_source=keyring.source_label, detail=detail)
    except auth.KeyUnavailable as exc:
        add("load_keys()", "失败", key_source="不可用",
            detail=f"密钥{('缺失' if exc.reason == 'missing' else '损坏')}，请在下方生成")

    new_token = None
    clear_cookie = False
    if keyring is not None:
        token = request.cookies.get(auth.AUTH_COOKIE_NAME)
        if not token:
            add("verify_credential()", "跳过",
                detail="请求未携带凭据 cookie，请先登录")
        else:
            result = auth.verify_credential(keyring, token)
            remaining = auth.format_remaining(result.remaining_seconds) if result.ok else "0s"
            add("verify_credential()", result.status, key_source=result.key_used or "—",
                remaining=remaining, detail=result.reason or f"用户 {result.username} 放行")
            if result.new_token:
                new_token = result.new_token
                add("issue_credential()", "续期签发", key_source="当前密钥",
                    remaining=remaining, detail=result.reason)
            if result.status in ("expired", "tampered"):
                clear_cookie = True
                add("logout_expired()", "已登出",
                    detail="凭据失效，清除 cookie 并回到登录页")

    resp = make_response(render_template(
        "auth_flow.html", events=events, keys_ok=keyring is not None,
        sliding=auth.format_remaining(auth.SLIDING_WINDOW_SECONDS),
        absolute=auth.format_remaining(auth.ABSOLUTE_EXPIRY_SECONDS),
        grace=auth.format_remaining(auth.ROTATION_GRACE_SECONDS),
    ))
    if new_token:
        resp.set_cookie(auth.AUTH_COOKIE_NAME, new_token, httponly=True, samesite="Lax")
    if clear_cookie:
        auth.logout_expired(resp)
    return resp


@app.route("/auth-flow/generate-key", methods=["POST"])
def auth_generate_key():
    """密钥缺失/损坏时的生成入口：自生成并原子落盘，而不是 500。"""
    auth.generate_keys()
    return redirect(url_for("auth_flow"))


@app.route("/auth-flow/rotate-key", methods=["POST"])
def auth_rotate_key():
    """轮换：原子替换，旧密钥留 24 小时宽限期仅用于验签。"""
    auth.rotate_keys()
    return redirect(url_for("auth_flow"))


if __name__ == "__main__":
    app.run(debug=True)
