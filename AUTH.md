# 认证会话子系统（auth/session.py）

登录门禁原先内联在 `app.py` 的 `before_request`，现拆为四个可独立调用的函数：

| 函数 | 职责 |
| --- | --- |
| `load_secret_key()` | 装载密钥：外部环境变量优先，其次 `instance/secret_keys.json` |
| `issue_credential(username, state)` | 用当前密钥 HMAC-SHA256 签发凭据，同时写入滑动与绝对到期 |
| `verify_credential(token, state)` | 验签 → 查滑动/绝对到期 → 通过后滑动续期（不绕开校验） |
| `end_session(reason, username)` | 过期/被拒时登出并返回清 cookie 指令 |

`protect_request()` 只是 `before_request` 的纯函数封装；`/auth-flow` 页面按时间线
回放每次调用，并显示两栏：**密钥来源** 与 **凭据剩余有效期**。

## 三处互相咬住的决策

1. **密钥来源（自生成落盘 vs 外部源）**
   - 默认不静默自生成：密钥缺失/损坏时页面给“立即生成”入口而不是 500。
   - 多副本部署必须设置环境变量 `SALES_SECRET_KEY`：所有副本共享同一密钥，
     签名才能互认；此时密钥不落盘，也就不会随版本库泄漏。
   - 自生成密钥只写到 `instance/secret_keys.json`（已在 `.gitignore`），仅供单机演示。
2. **滑动续期 + 绝对到期**
   - 滑动窗口默认 30 分钟不活跃失效；绝对到期默认 12 小时，只增不减。
   - 续期只把 `sliding_exp` 向后推满一个窗口，且永远 `min(now+窗口, absolute_exp)`；
     因此凭据被窃后最多用到绝对到期，活跃用户也不会被无限续期。
3. **轮换原子替换 + 24h 宽限**
   - `rotate_secret_key()` 先写临时文件再 `os.replace`，current/旧密钥同一文件原子切换。
   - 旧 current 进入 `grace`，保留 24 小时仍可验签；旧会话首次命中时照常放行，
     并在“通过完整校验之后”用新密钥重新签发（续期永不绕开校验）。超期旧密钥自动清除。

## 异常走向

- 密钥缺失：`/auth-flow`、`/login` 200 展示生成入口；受保护页 302 到 `/login`。
- 密钥文件损坏：损坏文件备份为 `secret_keys.json.corrupt.<ts>`，页面同样给生成入口。
- cookie 被篡改/签名不符：直接 302 拒绝并清 cookie，时间线记录“签名不匹配”。
- 宽限期内旧密钥签名：正常放行，页面显示“旧密钥宽限期内验签”，随后自动换新密钥。
- 滑动超时/绝对到期：分别记录原因并登出。

## 验证

```bash
python -m pytest -q tests/test_auth_flow.py
python -m flask --app app run   # 打开 http://127.0.0.1:5000/auth-flow
```

演示账号：`pparker / abc123`（沿用 `hashed_pw.pkl` 的 bcrypt 摘要）。
