#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pixiv 画师新作自动抢评论。

流程：
1. 用 refresh_token 走 App API 认证（pixivkit.AppPixivAPI.auth），顺带拿到当前账号 user_id；
2. 用 App API 拉取被监控画师的最新作品列表（user_illusts，含插画与漫画）；
3. 与本地状态文件 seen_posts.json 对比，找出新作品；
4. 对每个新作品发评论（评论走 Web API，需要 PHPSESSID，见 .github/workflows/auto_comment.yml）；
5. 评论结果写回状态文件，由 GitHub Actions 提交回仓库。

环境变量：
    PIXIV_REFRESH_TOKEN  必填，Pixiv refresh_token
    PIXIV_ARTIST_ID      必填，画师 id，可逗号分隔多个
    COMMENT_TEXT         可选，评论内容，用 | 分隔多条并循环使用；不设置则用内置默认值
    PIXIV_PHPSESSID      必填（发表评论时），浏览器 Cookie 里的 PHPSESSID
    STATE_FILE           可选，状态文件路径，默认 seen_posts.json
    DRY_RUN              =1 时只打印不评论
    MAX_NEW_PER_RUN      可选，单次最多评论多少个新作品，默认 5
    MAX_PAGES            可选，每个画师最多翻页数，默认 2
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets as pysecrets
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import requests

try:
    from pixivkit import AppPixivAPI, PixivError, WebPixivAPI
except ImportError as exc:  # pragma: no cover
    print(f"[FATAL] 缺少依赖 pixivkit，请先执行 pip install -r requirements.txt ({exc})")
    raise SystemExit(1)

# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #
DEFAULT_COMMENTS = ["前排", "好耶", "！！！"]
DEFAULT_STATE_FILE = "seen_posts.json"
# 要监控的画师 id。多个用英文逗号隔开，例如 "34931308,12345678"
ARTIST_IDS_DEFAULT = "34931308"
STATE_VERSION = 2

SLEEP_BETWEEN_COMMENTS = float(os.getenv("SLEEP_BETWEEN_COMMENTS", "3"))
MAX_NEW_PER_RUN = int(os.getenv("MAX_NEW_PER_RUN", "5"))
MAX_PAGES = int(os.getenv("MAX_PAGES", "2"))
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "30"))


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{ts}] {msg}", flush=True)


# --------------------------------------------------------------------------- #
# 自动登录取 refresh_token（OAuth PKCE，只用账号密码，不用你自己折腾 token）
# --------------------------------------------------------------------------- #
OAUTH_CLIENT_ID = "MOBrBDS8blbauoSck0ZfDbtuzpyT"
OAUTH_CLIENT_SECRET = "lsACyCD94FhDUtGTXi3QzcFE2uU1hqtDaKeqrdwj"
OAUTH_HASH_SECRET = "28c1fdd170a5204386cb1313c7077b34f83e4aaf4aa829ce78c231e05b0bae2c"
LOGIN_URL = (
    "https://app-api.pixiv.net/web/v1/login"
    "?code_challenge={challenge}&code_challenge_method=S256&client=pixiv-android"
)
APP_UA = "PixivIOSApp/7.13.3 (iOS 14.6; iPhone13,2)"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def make_pkce_pair() -> Tuple[str, str]:
    """生成 PKCE 的 code_verifier / code_challenge。"""
    verifier = _b64url(pysecrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def login_with_password(username: str, password: str) -> str:
    """用账号密码换 refresh_token，返回 refresh_token 字符串。"""
    verifier, challenge = make_pkce_pair()
    login_url = LOGIN_URL.format(challenge=challenge)

    print("\n" + "=" * 60)
    print("请用浏览器打开下面这个链接，登录你的 Pixiv 账号：")
    print(login_url)
    print("=" * 60)
    print("登录成功后页面会显示 「pixiv://account/login?code=xxxxx」这种跳转提示，")
    print("整段复制过来粘贴到下面（也可以只粘贴 code= 之后那一长串）。\n")

    try:
        pasted = input("粘贴 code（或整条链接）然后回车：").strip()
    except EOFError:
        raise RuntimeError("没有读到输入")

    m = re.search(r"code=([A-Za-z0-9_-]+)", pasted)
    code = m.group(1) if m else pasted.strip().strip('"').strip("'")
    if not code:
        raise RuntimeError("没有拿到 code")

    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S+00:00")
    headers = {
        "user-agent": APP_UA,
        "app-os": "ios",
        "app-os-version": "14.6",
        "x-client-time": now,
        "x-client-hash": hashlib.md5((now + OAUTH_HASH_SECRET).encode()).hexdigest(),
        "content-type": "application/x-www-form-urlencoded",
    }
    data = {
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
        "code": code,
        "code_verifier": verifier,
        "grant_type": "authorization_code",
        "include_policy": "true",
        "redirect_uri": "https://app-api.pixiv.net/web/v1/users/auth/pixiv/callback",
    }
    resp = requests.post(
        "https://oauth.secure.pixiv.net/auth/token",
        headers=headers,
        data=data,
        timeout=30,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"换取 refresh_token 失败：HTTP {resp.status_code} {resp.text[:300]}")
    payload = resp.json()
    token = payload.get("refresh_token")
    if not token:
        raise RuntimeError(f"响应里没有 refresh_token：{json.dumps(payload, ensure_ascii=False)[:300]}")
    return token


def _write_env(path: str, updates: Dict[str, str]) -> None:
    """把变量写进 .env（存在则替换，不存在则追加）。"""
    lines: List[str] = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()

    remaining = dict(updates)
    out: List[str] = []
    for line in lines:
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if m and m.group(1) in remaining:
            key = m.group(1)
            out.append(f"{key}={remaining.pop(key)}")
        else:
            out.append(line)

    if out and out[-1].strip():
        out.append("")
    for key, value in remaining.items():
        out.append(f"{key}={value}")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out).rstrip("\n") + "\n")
    print(f"已写入 {path}（该文件已被 .gitignore 忽略，不会被提交到 GitHub）")


def setup_token(username: str, password: str, env_file: str = ".env") -> None:
    """交互式登录：拿 refresh_token + PHPSESSID，写进 .env，并打印到屏幕上方便贴到 GitHub。"""
    refresh_token = login_with_password(username, password)
    user_id = refresh_token.split("_", 1)[0] if "_" in refresh_token else ""
    php_session_id = f"{user_id}_{refresh_token.split('_', 1)[1]}" if user_id else ""

    print("\n" + "#" * 60)
    print("# 下面两个值分别复制到 GitHub 的两个 Secret 里：")
    print("#" * 60)
    print(f"\n[PIXIV_REFRESH_TOKEN]\n{refresh_token}\n")
    if php_session_id:
        print(f"[PIXIV_PHPSESSID]\n{php_session_id}\n")
        print("（PHPSESSID 是从 refresh_token 里自动拼出来的，不用去浏览器翻 Cookie）")
    print("#" * 60)

    _write_env(env_file, {
        "PIXIV_REFRESH_TOKEN": refresh_token,
        "PIXIV_PHPSESSID": php_session_id,
        "PIXIV_ARTIST_ID": os.getenv("PIXIV_ARTIST_ID", "34931308"),
        "COMMENT_TEXT": os.getenv("COMMENT_TEXT", "前排|好耶|！！！"),
        "DRY_RUN": "0",
    })


# --------------------------------------------------------------------------- #
# 状态读写
# --------------------------------------------------------------------------- #
def load_state(path: str) -> Dict[str, Any]:
    """读取状态文件。不存在 / 损坏时返回全新状态（initialized=False）。"""
    if not os.path.exists(path):
        log(f"状态文件 {path} 不存在：首次运行，只记录不评论。")
        return {"version": STATE_VERSION, "initialized": False, "artists": {}, "comment_index": 0}

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log(f"[WARN] 状态文件解析失败（{exc}），按首次运行处理，旧记录已备份为 {path}.broken")
        try:
            os.replace(path, f"{path}.broken")
        except OSError:
            pass
        return {"version": STATE_VERSION, "initialized": False, "artists": {}, "comment_index": 0}

    # 兼容旧版扁平结构：{"34931308": [1, 2, 3]}
    if raw and all(isinstance(v, list) for v in raw.values()) and "artists" not in raw:
        log("检测到旧版状态格式，自动迁移。")
        artists = {str(k): {"seen": [int(i) for i in v]} for k, v in raw.items()}
        return {
            "version": STATE_VERSION,
            "initialized": bool(artists),
            "artists": artists,
            "comment_index": 0,
        }

    raw.setdefault("version", STATE_VERSION)
    raw.setdefault("initialized", False)
    raw.setdefault("artists", {})
    raw.setdefault("comment_index", 0)
    raw["artists"] = {str(k): v for k, v in raw["artists"].items()}
    return raw


def save_state(path: str, state: Dict[str, Any]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)
    log(f"状态已写回 {path}。")


def artist_bucket(state: Dict[str, Any], artist_id: str) -> Dict[str, Any]:
    bucket = state["artists"].setdefault(artist_id, {"seen": [], "last_seen": None})
    bucket.setdefault("seen", [])
    bucket.setdefault("last_seen", None)
    return bucket


def seen_set(state: Dict[str, Any], artist_id: str) -> Set[int]:
    return {int(x) for x in artist_bucket(state, artist_id)["seen"]}


def mark_seen(state: Dict[str, Any], artist_id: str, illust_ids: Iterable[int]) -> None:
    bucket = artist_bucket(state, artist_id)
    merged = sorted({int(x) for x in bucket["seen"]} | {int(x) for x in illust_ids})
    # 只保留最近 500 条，避免文件无限膨胀
    bucket["seen"] = merged[-500:]
    bucket["last_seen"] = datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# 配置解析
# --------------------------------------------------------------------------- #
def parse_artist_ids(raw: str) -> List[str]:
    ids: List[str] = []
    for part in raw.replace("，", ",").replace(" ", ",").split(","):
        part = part.strip()
        if part and part.isdigit() and part not in ids:
            ids.append(part)
        elif part:
            log(f"[WARN] 忽略非法画师 id：{part!r}")
    return ids


def parse_comments(raw: Optional[str]) -> List[str]:
    if not raw or not raw.strip():
        return list(DEFAULT_COMMENTS)
    if "|" in raw or "||" in raw:
        items = [x.strip() for x in raw.replace("||", "|").split("|")]
    elif "\n" in raw:
        items = [x.strip() for x in raw.splitlines()]
    else:
        items = [raw.strip()]
    items = [x for x in items if x]
    return items or list(DEFAULT_COMMENTS)


def next_comment(state: Dict[str, Any], comments: List[str]) -> Tuple[str, int]:
    """从 COMMENTS 里循环取一条，并推进全局游标。"""
    idx = int(state.get("comment_index", 0)) % len(comments)
    return comments[idx], (idx + 1) % len(comments)


# --------------------------------------------------------------------------- #
# Pixiv 客户端
# --------------------------------------------------------------------------- #
def build_app_api(refresh_token: str):
    """refresh_token 认证，返回 (api, user_id)。"""
    api = AppPixivAPI(timeout=REQUEST_TIMEOUT)
    try:
        token = api.auth(refresh_token=refresh_token)
    except PixivError as exc:
        body = (getattr(exc, "body", "") or "")[:400]
        hint = ""
        if "invalid_grant" in body or "400" in str(exc):
            hint = " → refresh_token 已失效/被吊销，请重新获取并更新 Secret PIXIV_REFRESH_TOKEN"
        elif "423" in body:
            hint = " → Pixiv 账号被限制登录，请先在浏览器正常登录一次解限"
        raise RuntimeError(f"Pixiv 认证失败：{exc}{hint}") from exc
    except Exception as exc:  # 网络层异常
        raise RuntimeError(f"Pixiv 认证时网络异常：{exc}") from exc

    user_id = getattr(api, "user_id", None)
    if not user_id:
        try:
            user_id = token.response.user.id  # type: ignore[attr-defined]
        except Exception:
            user_id = None
    if not user_id:
        raise RuntimeError("认证成功但拿不到 user_id，无法发表评论（检查 refresh_token 是否正确）")

    log(f"认证成功，当前账号 user_id = {user_id}")
    return api, str(user_id)


def fetch_artist_works(api, artist_id: str, pages: int) -> List[Dict[str, Any]]:
    """拉取画师最新作品（插画 + 漫画），按创建时间倒序去重返回。"""
    result: Dict[int, Dict[str, Any]] = {}
    offset: Optional[str] = None

    for page in range(max(1, pages)):
        try:
            resp = api.user_illusts(artist_id, type=None, offset=offset)
        except PixivError as exc:
            body = (getattr(exc, "body", "") or "")[:300]
            raise RuntimeError(f"获取画师 {artist_id} 作品列表失败：{exc} {body}".strip()) from exc
        except Exception as exc:
            raise RuntimeError(f"获取画师 {artist_id} 作品列表时网络异常：{exc}") from exc

        illusts = getattr(resp, "illusts", None) or []
        for item in illusts:
            try:
                pid = int(item.id)
            except (KeyError, TypeError, ValueError):
                continue
            result[pid] = item

        offset = getattr(resp, "next_url", None)
        if not offset or not illusts:
            break
        if page + 1 < pages:
            time.sleep(1)

    works = sorted(
        result.values(),
        key=lambda i: i.get("create_date", "") or "",
        reverse=True,
    )
    log(f"画师 {artist_id}：本次拉取到 {len(works)} 个作品。")
    return works


def post_comment(web_api, illust_id: int, user_id: str, text: str, dry_run: bool) -> None:
    """发表评论。失败抛异常，由上层记录并继续。"""
    if dry_run:
        log(f"[DRY_RUN] 跳过实际评论：illust_id={illust_id} text={text!r}")
        return
    if web_api is None:
        raise RuntimeError("缺少 PIXIV_PHPSESSID，无法调用 Web 评论接口")

    try:
        resp = web_api.comment.post_illust_comment(illust_id, user_id, comment=text)
    except PixivError as exc:
        raise RuntimeError(f"评论请求异常：{exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"评论请求网络异常：{exc}") from exc

    payload = resp if isinstance(resp, dict) else {}
    if isinstance(payload, dict) and payload.get("error"):
        detail = json.dumps(payload, ensure_ascii=False)[:300]
        raise RuntimeError(f"Pixiv 拒绝评论：{detail}")
    log(f"评论成功：illust_id={illust_id} text={text!r}")


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def run() -> int:
    refresh_token = (os.getenv("PIXIV_REFRESH_TOKEN") or "").strip()
    artist_raw = (os.getenv("PIXIV_ARTIST_ID") or "").strip() or ARTIST_IDS_DEFAULT
    php_session_id = (os.getenv("PIXIV_PHPSESSID") or "").strip()
    state_path = (os.getenv("STATE_FILE") or DEFAULT_STATE_FILE).strip()
    dry_run = (os.getenv("DRY_RUN") or "").strip() in {"1", "true", "True", "yes"}

    if not refresh_token:
        log("[FATAL] 未设置 PIXIV_REFRESH_TOKEN")
        return 2

    artists = parse_artist_ids(artist_raw)
    if not artists:
        log("[FATAL] PIXIV_ARTIST_ID 里没有合法画师 id")
        return 2

    comments = parse_comments(os.getenv("COMMENT_TEXT"))
    log(f"监控画师：{', '.join(artists)}；评论池：{comments}；DRY_RUN={dry_run}")

    api, user_id = build_app_api(refresh_token)

    web_api = None
    if php_session_id and not dry_run:
        web_api = WebPixivAPI(php_session_id, timeout=REQUEST_TIMEOUT)
        if str(web_api.user_id) != str(user_id):
            log(
                f"[WARN] PHPSESSID 属于 user_id={web_api.user_id}，"
                f"与 refresh_token 的 user_id={user_id} 不一致，评论会以 {web_api.user_id} 身份发出。"
            )
    elif not dry_run:
        log("[WARN] 未设置 PIXIV_PHPSESSID：只能监控，无法真正发表评论（需要 Web Cookie 才能发评论）。")

    state = load_state(state_path)
    first_run = not bool(state.get("initialized"))
    commented = 0
    failed = 0
    state_dirty = False

    for artist_id in artists:
        try:
            works = fetch_artist_works(api, artist_id, MAX_PAGES)
        except Exception as exc:
            log(f"[ERROR] 画师 {artist_id} 获取失败：{exc}")
            failed += 1
            continue

        if not works:
            log(f"[INFO] 画师 {artist_id} 暂无可访问作品（可能是私密/R18 未开放/接口为空），跳过。")
            continue

        ids = [int(w.id) for w in works]

        # ---------- 首次运行：只记录，不评论 ----------
        if first_run and not state["initialized"]:
            mark_seen(state, artist_id, ids)
            state_dirty = True
            log(f"[首次运行] 画师 {artist_id}：已将 {len(ids)} 个现有作品标记为已见，本次不评论。")
            continue

        known = seen_set(state, artist_id)
        new_works = [w for w in works if int(w.id) not in known]

        if not new_works:
            log(f"画师 {artist_id}：没有新作品。")
            continue

        # 按发布时间正序处理，保证最早发布的先评论
        new_works.sort(key=lambda w: w.get("create_date", "") or "")
        log(f"画师 {artist_id}：发现 {len(new_works)} 个新作品 → {[int(w.id) for w in new_works]}")

        for work in new_works:
            pid = int(work.id)
            title = work.get("title", "")
            if commented >= MAX_NEW_PER_RUN:
                log(f"[INFO] 已达单次上限 MAX_NEW_PER_RUN={MAX_NEW_PER_RUN}，剩余作品下次运行处理。")
                break

            text, new_idx = next_comment(state, comments)
            try:
                post_comment(web_api, pid, user_id, text, dry_run)
                state["comment_index"] = new_idx
                commented += 1
            except Exception as exc:
                failed += 1
                log(f"[ERROR] 评论失败 illust_id={pid} 《{title}》：{exc}")
                # 评论失败不阻断，但仍写入已见，避免每 5 分钟反复轰炸同一个作品
            finally:
                mark_seen(state, artist_id, [pid])
                state_dirty = True

            time.sleep(SLEEP_BETWEEN_COMMENTS)

    # 首次运行跑完了，标记 initialized
    if first_run and not state["initialized"]:
        state["initialized"] = True
        state_dirty = True

    if state_dirty:
        save_state(state_path, state)
    else:
        log("状态无变化。")

    log(f"本次结束：评论 {commented} 条，失败 {failed} 项。")
    # 失败不返回非 0，防止 Actions 因为单个作品失败而红叉；日志里已有明确 ERROR
    return 0


def main() -> int:
    """入口：默认跑监控；带 --setup 则走交互式登录拿 token。"""
    if len(sys.argv) > 1 and sys.argv[1] in {"--setup", "setup", "--login"}:
        try:
            user = input("Pixiv 账号（邮箱/用户名/Pixiv ID）：").strip()
            pw = input("Pixiv 密码（输入时不会显示，也不会被保存）：").strip()
            setup_token(user, pw, env_file=os.getenv("ENV_FILE", ".env"))
            print("\n完成。接下来把上面两个值填进 GitHub 的 Secrets（README「第五步」）。")
            return 0
        except Exception as exc:
            print(f"[FATAL] 登录流程失败：{exc}")
            return 1
    return run()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except KeyboardInterrupt:
        log("被中断。")
        sys.exit(130)
    except Exception as exc:  # 兜底
        log(f"[FATAL] 未捕获异常：{type(exc).__name__}: {exc}")
        sys.exit(1)
