#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pixiv 画师新作自动抢评论。"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from pixivkit import PixivError, WebPixivAPI
from pixivkit.web_client import WebClient

# 要监控的画师 id。多个用英文逗号隔开，例如 "34931308,12345678"
ARTIST_IDS_DEFAULT = "34931308"
DEFAULT_COMMENTS = ["前排", "好耶", "！！！"]
DEFAULT_STATE_FILE = "seen_posts.json"
STATE_VERSION = 2

SLEEP_BETWEEN_COMMENTS = float(os.getenv("SLEEP_BETWEEN_COMMENTS", "3"))
MAX_NEW_PER_RUN = int(os.getenv("MAX_NEW_PER_RUN", "5"))
MAX_PAGES = int(os.getenv("MAX_PAGES", "2"))
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "30"))


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{ts}] {msg}", flush=True)


def patch_webpixiv_csrf() -> None:
    """修 pixivkit 0.1.0 的 CSRF token 提取（新版页面是双重转义）。"""

    def fetch_token(self):
        url = f"{self.host}/settings/account"
        response = self.session.get(
            url,
            headers={
                "Referer": self.host,
                "Cookie": self.cookie,
                "User-Agent": self.BROWSER_HEADERS["User-Agent"],
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,ja;q=0.7",
            },
            timeout=self.timeout,
            verify=self.verify,
        )
        html = response.text
        for pattern in (
            r'\\"token\\":\\"([a-f0-9]{20,})\\"',
            r'"token":"([a-f0-9]{20,})"',
            r'token\\?"\s*:\s*"([a-f0-9]{20,})',
            r'token[^a-zA-Z0-9]{1,6}([a-f0-9]{32})',
        ):
            m = re.search(pattern, html)
            if m:
                self.csrf_token = m.group(1)
                return m.group(1)
        raise PixivError("Unable to get CSRF Token（Cookie 可能已失效）",
                         header=response.headers, body=html[:2000])

    WebClient.fetch_token = fetch_token


patch_webpixiv_csrf()


def _blank_state() -> Dict[str, Any]:
    return {"version": STATE_VERSION, "initialized": False, "artists": {}, "comment_index": 0}


def load_state(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        log(f"状态文件 {path} 不存在：首次运行，只记录不评论。")
        return _blank_state()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log(f"[WARN] 状态文件解析失败（{exc}），按首次运行处理")
        try:
            os.replace(path, f"{path}.broken")
        except OSError:
            pass
        return _blank_state()

    if not isinstance(raw, dict):
        return _blank_state()

    if raw and all(isinstance(v, list) for v in raw.values()) and "artists" not in raw:
        log("检测到旧版状态格式，自动迁移。")
        artists = {str(k): {"seen": [int(i) for i in v]} for k, v in raw.items()}
        return {"version": STATE_VERSION, "initialized": bool(artists),
                "artists": artists, "comment_index": 0}

    raw.setdefault("version", STATE_VERSION)
    raw.setdefault("initialized", False)
    raw.setdefault("comment_index", 0)
    raw.setdefault("artists", {})
    if not isinstance(raw["artists"], dict):
        raw["artists"] = {}
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
    bucket["seen"] = merged[-500:]
    bucket["last_seen"] = datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_artist_ids(raw: str) -> List[str]:
    ids: List[str] = []
    for part in (raw or "").replace("，", ",").replace(" ", ",").split(","):
        part = part.strip()
        if part.isdigit() and part not in ids:
            ids.append(part)
        elif part:
            log(f"[WARN] 忽略非法画师 id：{part!r}")
    return ids


def parse_comments(raw: Optional[str]) -> List[str]:
    if not raw or not raw.strip():
        return list(DEFAULT_COMMENTS)
    if "\n" in raw:
        items = raw.splitlines()
    else:
        items = raw.replace("||", "|").split("|")
    items = [x.strip() for x in items if x.strip()]
    return items or list(DEFAULT_COMMENTS)


def next_comment(state: Dict[str, Any], comments: List[str]) -> Tuple[str, int]:
    idx = int(state.get("comment_index", 0)) % len(comments)
    return comments[idx], (idx + 1) % len(comments)


def build_web_api(php_session_id: str) -> WebPixivAPI:
    if not php_session_id:
        raise RuntimeError("未设置 PIXIV_PHPSESSID")
    if "_" not in php_session_id:
        log("[WARN] PHPSESSID 里没有下划线，可能是未登录状态的匿名 Cookie，评论会失败。")
    api = WebPixivAPI(php_session_id, timeout=REQUEST_TIMEOUT)
    try:
        me = api.user.get_user_info(api.user_id, full=1)
    except Exception as exc:
        raise RuntimeError(f"Pixiv 会话校验失败（Cookie 可能已失效）：{exc}") from exc
    if getattr(me, "error", True):
        raise RuntimeError("Pixiv 会话无效：请重新登录 pixiv.net，取新的 PHPSESSID 更新 Secret")
    name = (getattr(me, "body", {}) or {}).get("name", "?")
    log(f"Cookie 登录有效：{name} (user_id={api.user_id})")
    return api


def fetch_artist_works(api: WebPixivAPI, artist_id: str, pages: int) -> List[Dict[str, Any]]:
    try:
        prof = api.user.get_profile_all(artist_id)
    except Exception as exc:
        raise RuntimeError(f"获取画师 {artist_id} 作品列表失败：{exc}") from exc
    if getattr(prof, "error", True):
        raise RuntimeError(f"画师 {artist_id} 作品列表返回错误：{getattr(prof, 'message', '')}")

    body = getattr(prof, "body", {}) or {}
    buckets = []
    for key in ("illusts", "manga"):
        d = body.get(key) or {}
        if isinstance(d, dict):
            buckets.extend(int(k) for k in d if str(k).isdigit())

    ids = sorted(set(buckets), reverse=True)
    if not ids:
        log(f"画师 {artist_id}：没有公开作品。")
        return []

    limit = max(1, pages) * 30
    wanted = ids[:limit]
    details: List[Dict[str, Any]] = []

    for i in range(0, len(wanted), 48):
        chunk = wanted[i:i + 48]
        try:
            resp = api.user.get_profile_illusts(artist_id, chunk)
        except Exception as exc:
            raise RuntimeError(f"获取画师 {artist_id} 作品详情失败：{exc}") from exc
        got = (getattr(resp, "body", {}) or {}).get("works", {}) or {}
        for pid, info in got.items():
            if isinstance(info, dict):
                info = dict(info)
                info.setdefault("id", pid)
                details.append(info)

    details.sort(key=lambda d: str(d.get("createDate") or ""), reverse=True)
    log(f"画师 {artist_id}：共 {len(ids)} 个作品，本次检查最新 {len(details)} 个。")
    return details


def post_comment(api: WebPixivAPI, illust_id: int, user_id: str, text: str, dry_run: bool) -> None:
    if dry_run:
        log(f"[DRY_RUN] 跳过实际评论：illust_id={illust_id} text={text!r}")
        return
    try:
        resp = api.comment.post_illust_comment(illust_id, user_id, comment=text)
    except PixivError as exc:
        raise RuntimeError(f"评论请求异常：{exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"评论请求网络异常：{exc}") from exc

    payload = resp if isinstance(resp, dict) else {}
    if payload.get("error"):
        raise RuntimeError(f"Pixiv 拒绝评论：{json.dumps(payload, ensure_ascii=False)[:300]}")
    cid = (payload.get("body") or {}).get("comment_id", "?")
    log(f"评论成功：illust_id={illust_id} text={text!r} comment_id={cid}")


def run() -> int:
    php_session_id = (os.getenv("PIXIV_PHPSESSID") or "").strip()
    artist_raw = (os.getenv("PIXIV_ARTIST_ID") or "").strip() or ARTIST_IDS_DEFAULT
    state_path = (os.getenv("STATE_FILE") or DEFAULT_STATE_FILE).strip()
    dry_run = (os.getenv("DRY_RUN") or "").strip() in {"1", "true", "True", "yes"}

    if not php_session_id:
        log("[FATAL] 未设置 PIXIV_PHPSESSID")
        return 2

    artists = parse_artist_ids(artist_raw)
    if not artists:
        log("[FATAL] 没有合法的画师 id")
        return 2

    comments = parse_comments(os.getenv("COMMENT_TEXT"))
    log(f"监控画师：{', '.join(artists)}；评论池：{comments}；DRY_RUN={dry_run}")

    try:
        api = build_web_api(php_session_id)
    except Exception as exc:
        log(f"[FATAL] {exc}")
        return 2

    user_id = str(api.user_id)
    state = load_state(state_path)
    first_run = not bool(state.get("initialized"))
    commented = 0
    failed = 0
    state_dirty = False

    for artist_id in artists:
        try:
            works = fetch_artist_works(api, artist_id, MAX_PAGES)
        except Exception as exc:
            log(f"[ERROR] 画师 {artist_id}：{exc}")
            failed += 1
            continue

        if not works:
            continue

        ids = [int(w["id"]) for w in works if str(w.get("id", "")).isdigit()]

        if first_run and not state.get("initialized"):
            mark_seen(state, artist_id, ids)
            state_dirty = True
            log(f"[首次运行] 画师 {artist_id}：{len(ids)} 个现有作品已标记为已见，本次不评论。")
            continue

        known = seen_set(state, artist_id)
        new_works = [w for w in works if int(w["id"]) not in known]
        if not new_works:
            log(f"画师 {artist_id}：没有新作品。")
            continue

        new_works.sort(key=lambda w: str(w.get("createDate") or ""))
        log(f"画师 {artist_id}：发现 {len(new_works)} 个新作品 → {[w['id'] for w in new_works]}")

        for work in new_works:
            pid = int(work["id"])
            title = work.get("title", "")
            if commented >= MAX_NEW_PER_RUN:
                log(f"[INFO] 已达单次上限 {MAX_NEW_PER_RUN} 条，剩下的下次运行处理。")
                break

            text, new_idx = next_comment(state, comments)
            try:
                post_comment(api, pid, user_id, text, dry_run)
                state["comment_index"] = new_idx
                commented += 1
            except Exception as exc:
                failed += 1
                log(f"[ERROR] 评论失败 illust_id={pid} 《{title}》：{exc}")
            finally:
                mark_seen(state, artist_id, [pid])
                state_dirty = True

            time.sleep(SLEEP_BETWEEN_COMMENTS)

    if first_run and not state.get("initialized"):
        state["initialized"] = True
        state_dirty = True

    if state_dirty:
        save_state(state_path, state)
    else:
        log("状态无变化。")

    log(f"本次结束：评论 {commented} 条，失败 {failed} 项。")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(run())
    except SystemExit:
        raise
    except KeyboardInterrupt:
        log("被中断。")
        sys.exit(130)
    except Exception as exc:
        log(f"[FATAL] 未捕获异常：{type(exc).__name__}: {exc}")
        sys.exit(1)
