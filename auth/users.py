"""演示账号：沿用仓库 hashed_pw.pkl 里的 bcrypt 摘要校验。"""

from __future__ import annotations

import pickle
from functools import lru_cache
from pathlib import Path

import bcrypt

_USERS = {
    "pparker": {"name": "Peter Parker", "index": 0},
    "rmiller": {"name": "Rebecca Miller", "index": 1},
}


@lru_cache(maxsize=1)
def _hashes() -> list[str]:
    path = Path(__file__).resolve().parent.parent / "hashed_pw.pkl"
    with path.open("rb") as handle:
        return [h if isinstance(h, str) else h.decode() for h in pickle.load(handle)]


def authenticate(username: str, password: str) -> str | None:
    """成功返回显示名，失败返回 None。"""

    user = _USERS.get(username)
    if user is None:
        return None
    try:
        digest = _hashes()[user["index"]]
    except (OSError, pickle.PickleError, IndexError):
        return None
    if bcrypt.checkpw(password.encode("utf-8"), digest.encode("utf-8")):
        return user["name"]
    return None
