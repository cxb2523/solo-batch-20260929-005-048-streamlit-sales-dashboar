"""Flask 版销售看板：登录门禁由 auth/session.py 的四个函数承担。

启动：python -m flask --app app run
页面：/login、/（看板，需登录）、/auth-flow（时间线回放）、/rotate-key
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pandas as pd
from flask import (
    Flask,
    Response,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from auth.session import (
    AuthFlowLog,
    end_session,
    generate_secret_key,
    get_settings,
    init_app,
    issue_credential,
    load_secret_key,
    protect_request,
    rotate_secret_key,
)
from auth.users import authenticate

PUBLIC_PATHS = {"/login", "/auth-flow", "/generate-key", "/healthz"}


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY="flask-side-messages",
        AUTH_KEY_ENV_VAR="SALES_SECRET_KEY",
        AUTH_KEY_FILE=str(Path(__file__).parent / "instance" / "secret_keys.json"),
        AUTH_COOKIE_NAME="session_token",
        AUTH_COOKIE_SECURE=False,
        AUTH_SLIDING_WINDOW=30 * 60,
        AUTH_ABSOLUTE_WINDOW=12 * 60 * 60,
        AUTH_GRACE_SECONDS=24 * 60 * 60,
        AUTH_AUTO_GENERATE_KEY=False,
    )
    if config:
        app.config.update(config)
    init_app(app)

    @app.before_request
    def login_gate() -> Response | None:
        decision = protect_request(
            cookie_token=request.cookies.get(get_settings().cookie_name),
            public_paths=PUBLIC_PATHS,
            path=request.path,
        )
        g.key_state = decision["state"]
        g.verification = decision["verification"]
        g.clear_cookie = decision["clear_cookie"]
        if decision["allow"]:
            return None
        return redirect(decision["redirect"])

    @app.after_request
    def apply_cookie(response: Response) -> Response:
        if getattr(g, "clear_cookie", None):
            response.delete_cookie(g.clear_cookie)
        verification = getattr(g, "verification", None)
        if verification is not None and verification.ok and verification.renewed:
            response.set_cookie(
                get_settings().cookie_name,
                verification.renewed_credential.token,
                max_age=get_settings().absolute_window,
                httponly=True,
                secure=get_settings().cookie_secure,
                samesite="Lax",
            )
        return response

    @app.route("/login", methods=["GET", "POST"])
    def login():
        state = load_secret_key()
        error = None
        if request.method == "POST":
            if not state.ready:
                error = "签名密钥尚未就绪，请先生成密钥。"
            else:
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                display_name = authenticate(username, password)
                if display_name is None:
                    AuthFlowLog.instance().record(
                        "login", "账号或密码错误", username=username, rejected=True
                    )
                    error = "用户名或密码错误。"
                else:
                    credential = issue_credential(username, state)
                    response = redirect(request.args.get("next") or url_for("dashboard"))
                    response.set_cookie(
                        get_settings().cookie_name,
                        credential.token,
                        max_age=get_settings().absolute_window,
                        httponly=True,
                        secure=get_settings().cookie_secure,
                        samesite="Lax",
                    )
                    g.display_name = display_name
                    return response
        return render_template(
            "login.html",
            key_state=state,
            key_env=get_settings().key_env_var,
            error=error,
        )

    @app.post("/logout")
    def logout():
        verification = getattr(g, "verification", None)
        username = verification.username if verification else None
        end_session("logout", username)
        response = redirect(url_for("login"))
        response.delete_cookie(get_settings().cookie_name)
        return response

    @app.post("/generate-key")
    def make_key():
        generate_secret_key()
        return redirect(url_for("auth_flow"))

    @app.post("/rotate-key")
    def rotate_key():
        rotate_secret_key()
        return redirect(url_for("auth_flow"))

    @app.route("/healthz")
    def healthz():
        return {"ok": True, "key": g.key_state.status}

    @app.route("/")
    def dashboard():
        verification = g.verification
        state = g.key_state
        frame = _load_sales()
        totals = {
            "total_sales": int(frame["Total"].sum()),
            "avg_rating": round(frame["Rating"].mean(), 1),
            "avg_transaction": round(frame["Total"].mean(), 2),
            "rows": len(frame),
        }
        by_city = (
            frame.groupby("City")["Total"].sum().round(0).sort_values(ascending=False)
        )
        return render_template(
            "dashboard.html",
            username=verification.username,
            remaining=verification.remaining(get_settings().now()),
            signed_by=verification.originally_signed_by or verification.signed_by,
            key_state=state,
            totals=totals,
            by_city=by_city.to_dict(),
        )

    @app.route("/auth-flow")
    def auth_flow():
        settings = get_settings()
        state = getattr(g, "key_state", None) or load_secret_key(settings)
        verification = getattr(g, "verification", None)
        token = request.cookies.get(settings.cookie_name)
        remaining = None
        if verification is not None and verification.ok:
            remaining = verification.remaining(settings.now())
        events = AuthFlowLog.instance().events()
        return render_template(
            "auth_flow.html",
            key_state=state,
            events=events,
            remaining=remaining,
            verification=verification,
            has_cookie=bool(token),
            settings=settings,
            fmt_ts=_fmt_ts,
            fmt_dur=_fmt_dur,
        )

    return app


def _fmt_ts(ts):
    if ts is None:
        return "-"
    return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")


def _fmt_dur(seconds):
    seconds = int(seconds)
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}小时{minutes}分{secs}秒"
    if minutes:
        return f"{minutes}分{secs}秒"
    return f"{secs}秒"


def _load_sales() -> pd.DataFrame:
    path = Path(__file__).parent / "supermarkt_sales.xlsx"
    frame = pd.read_excel(
        path,
        engine="openpyxl",
        sheet_name="Sales",
        skiprows=3,
        usecols="B:R",
        nrows=1000,
    )
    return frame


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
