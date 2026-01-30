#!/usr/bin/env python3
import os
import sys
import json
import re
import time
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

GITHUB_API = "https://api.github.com"
ROOT = Path(__file__).resolve().parent.parent

EXCLUDE_FULL_NAMES = {
    "nomi-sec/PoC-in-GitHub",
    "LulzSecToolkit/Lulz4Life",
}

CVE_RE = re.compile(r"CVE-(\d{4})-(\d{3,})", re.IGNORECASE)

DEFAULT_SEARCH_THROTTLE_SECONDS = 2.2  # safe-ish for Search API; adjust with --throttle-seconds


# ---------- utils ----------

def ensure_token(token: str) -> None:
    if not token or len(token.strip()) < 10:
        print("ERROR: GITHUB_TOKEN is missing.", file=sys.stderr)
        sys.exit(2)


def gh_headers(token: str) -> dict:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "KvitraX-PoC-Registry-Collector",
    }


def _parse_int(v: Optional[str], default: int = 0) -> int:
    try:
        return int(v) if v is not None else default
    except Exception:
        return default


def _sleep_until(reset_epoch: int, extra_seconds: float = 2.0) -> None:
    now = int(time.time())
    wait = max(1, reset_epoch - now) + int(extra_seconds)
    print(f"[!] Rate limit: sleeping {wait}s until reset (reset_epoch={reset_epoch}, now={now})")
    time.sleep(wait)


def gh_request(
    method: str,
    url: str,
    token: str,
    params: dict | None = None,
    *,
    throttle_seconds: float = 0.0,
    max_retries: int = 6,
) -> requests.Response:
    """
    A resilient GitHub requester:
    - optionally throttles (sleep) before request
    - handles 403 rate limit by sleeping until reset and retrying
    - handles Retry-After if present (secondary limit)
    """
    s = requests.Session()
    headers = gh_headers(token)

    for attempt in range(1, max_retries + 1):
        if throttle_seconds and throttle_seconds > 0:
            time.sleep(throttle_seconds)

        r = s.request(method, url, headers=headers, params=params, timeout=45)

        # Success
        if r.status_code < 400:
            return r

        # Try to detect rate limits / secondary limits
        msg = ""
        try:
            j = r.json()
            msg = str(j.get("message", "")) if isinstance(j, dict) else ""
        except Exception:
            msg = r.text or ""

        msg_l = msg.lower()

        # Respect Retry-After if present
        retry_after = _parse_int(r.headers.get("Retry-After"), default=0)
        if retry_after > 0:
            print(f"[!] Retry-After={retry_after}s (status={r.status_code}) on {url}")
            time.sleep(retry_after + 1)
            continue

        # Rate limit exceeded => sleep until reset
        if r.status_code == 403 and ("rate limit" in msg_l or "secondary rate limit" in msg_l):
            reset_epoch = _parse_int(r.headers.get("X-RateLimit-Reset"), default=0)
            remaining = _parse_int(r.headers.get("X-RateLimit-Remaining"), default=-1)
            limit = _parse_int(r.headers.get("X-RateLimit-Limit"), default=-1)

            print(f"[!] Rate limit hit (attempt {attempt}/{max_retries}) "
                  f"remaining={remaining} limit={limit} reset={reset_epoch} url={url}")
            if reset_epoch > 0:
                _sleep_until(reset_epoch, extra_seconds=3.0)
                continue

            # If no reset header, fallback: exponential backoff
            backoff = min(120, 2 ** attempt)
            print(f"[!] No reset header, backing off {backoff}s. Message: {msg}")
            time.sleep(backoff)
            continue

        # Other errors: retry with backoff a bit, then give up
        if attempt < max_retries and r.status_code in (500, 502, 503, 504):
            backoff = min(60, 2 ** attempt)
            print(f"[!] Server error {r.status_code}, retrying in {backoff}s")
            time.sleep(backoff)
            continue

        # Final fail
        raise RuntimeError(f"GitHub request failed: {r.status_code} {msg} (url={url})")

    raise RuntimeError(f"GitHub request failed after {max_retries} retries (url={url})")


def gh_get_json(
    url: str,
    token: str,
    params: dict | None = None,
    *,
    throttle_seconds: float = 0.0,
) -> dict:
    r = gh_request("GET", url, token, params=params, throttle_seconds=throttle_seconds)
    return r.json()


# ---------- CVE helpers ----------

def cve_search_variants(cve: str) -> list[str]:
    cve = cve.upper().strip()
    parts = cve.split("-")
    if len(parts) != 3:
        return [cve]

    year = parts[1]
    seq = parts[2]

    variants = [f"CVE-{year}-{seq}"]
    seq_unpadded = seq.lstrip("0") or "0"
    if seq_unpadded != seq:
        variants.append(f"CVE-{year}-{seq_unpadded}")

    out: list[str] = []
    seen: set[str] = set()
    for v in variants:
        if v not in seen:
            out.append(v)
            seen.add(v)
    return out


def normalize_cve(year: str, seq: str) -> str:
    seq = str(seq).strip()
    if len(seq) < 4:
        seq = seq.zfill(4)
    return f"CVE-{year}-{seq}".upper()


def repo_mentions_any_variant(repo: dict, variants: list[str]) -> bool:
    name = (repo.get("name") or "")
    full_name = (repo.get("full_name") or "")
    desc = (repo.get("description") or "")
    topics = repo.get("topics") or []

    blob = "\n".join([
        str(name),
        str(full_name),
        str(desc),
        " ".join([str(t) for t in topics]),
    ]).upper()

    for v in variants:
        if v.upper() in blob:
            return True
    return False


def repo_readme_mentions_any_variant(token: str, full_name: str, variants: list[str]) -> bool:
    url = f"{GITHUB_API}/repos/{full_name}/readme"
    try:
        data = gh_get_json(url, token, throttle_seconds=0.0)
    except Exception:
        return False

    content_b64 = data.get("content") or ""
    if not content_b64:
        return False

    try:
        import base64
        text = base64.b64decode(content_b64).decode("utf-8", errors="ignore").upper()
    except Exception:
        return False

    for v in variants:
        if v.upper() in text:
            return True
    return False


# ---------- GitHub search ----------

def search_repos(
    token: str,
    query: str,
    per_page: int = 100,
    page: int = 1,
    *,
    throttle_seconds: float = DEFAULT_SEARCH_THROTTLE_SECONDS,
) -> list[dict]:
    url = f"{GITHUB_API}/search/repositories"
    params = {
        "q": query,
        "per_page": per_page,
        "page": page,
        "sort": "indexed",
        "order": "desc",
    }

    data = gh_get_json(url, token, params=params, throttle_seconds=throttle_seconds)
    items = data.get("items", [])

    filtered = [repo for repo in items if repo.get("full_name") not in EXCLUDE_FULL_NAMES]
    if len(items) != len(filtered):
        print(f"[!] Filtered out {len(items) - len(filtered)} aggregator repos")

    return filtered


def search_repos_for_cve(
    token: str,
    cve: str,
    pages: int = 3,
    verify_readme: bool = True,
    *,
    throttle_seconds: float = DEFAULT_SEARCH_THROTTLE_SECONDS,
) -> list[dict]:
    variants = cve_search_variants(cve)

    or_part = variants[0] if len(variants) == 1 else "(" + " OR ".join(variants) + ")"
    pages = max(1, min(int(pages), 10))

    queries = [
        ("name-only", f"{or_part} in:name"),
        ("fallback", f"{or_part} in:name,description,readme"),
    ]

    seen_ids: set[int] = set()
    all_items: list[dict] = []

    for label, q in queries:
        scanned = 0
        kept = 0
        kept_meta = 0
        kept_readme = 0

        for p in range(1, pages + 1):
            items = search_repos(token, query=q, per_page=100, page=p, throttle_seconds=throttle_seconds)
            if not items:
                break
            scanned += len(items)

            for repo in items:
                rid = repo.get("id")
                if not isinstance(rid, int) or rid in seen_ids:
                    continue

                if repo_mentions_any_variant(repo, variants):
                    seen_ids.add(rid)
                    all_items.append(repo)
                    kept += 1
                    kept_meta += 1
                    continue

                if verify_readme and "readme" in q:
                    full_name = repo.get("full_name") or ""
                    if full_name and repo_readme_mentions_any_variant(token, full_name, variants):
                        seen_ids.add(rid)
                        all_items.append(repo)
                        kept += 1
                        kept_readme += 1

        if scanned:
            print(
                f"[+] Query {label}: scanned={scanned} kept={kept} "
                f"(meta={kept_meta}, readme={kept_readme}) pages={pages}"
            )

    if all_items:
        print(f"[+] Found {len(all_items)} repos for {cve} (variants: {variants})")
    return all_items


# ---------- filesystem ----------

def cve_path(cve: str) -> Path:
    year = cve.split("-")[1]
    return ROOT / year / f"{cve}.json"


def load_existing(path: Path) -> list[dict]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in {path}: {e}")

    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]

    if isinstance(data, dict):
        for key in ("entries", "items", "repos", "repositories"):
            if isinstance(data.get(key), list):
                return [x for x in data[key] if isinstance(x, dict)]
        if "id" in data and "full_name" in data:
            return [data]
        raise RuntimeError(f"Unsupported JSON object in {path}. Keys: {list(data.keys())}")

    raise RuntimeError(f"Unsupported JSON root type in {path}: {type(data).__name__}")


def save(path: Path, data: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------- normalization & merge ----------

def normalize_repo(repo: dict) -> dict:
    return {
        "id": repo["id"],
        "name": repo["name"],
        "full_name": repo["full_name"],
        "owner": {
            "login": repo["owner"]["login"],
            "id": repo["owner"]["id"],
            "avatar_url": repo["owner"]["avatar_url"],
            "html_url": repo["owner"]["html_url"],
            "user_view_type": repo["owner"].get("user_view_type"),
        },
        "html_url": repo["html_url"],
        "description": repo.get("description"),
        "fork": repo["fork"],
        "created_at": repo["created_at"],
        "updated_at": repo["updated_at"],
        "pushed_at": repo["pushed_at"],
        "stargazers_count": repo["stargazers_count"],
        "watchers_count": repo["watchers_count"],
        "forks_count": repo["forks_count"],
        "topics": repo.get("topics", []),
        "visibility": repo.get("visibility"),
    }


def merge(existing: list[dict], found: list[dict]) -> list[dict]:
    safe_existing = [e for e in existing if isinstance(e, dict) and "id" in e]
    known_ids = {e["id"] for e in safe_existing}

    added = 0
    for repo in found:
        if repo.get("id") not in known_ids:
            safe_existing.append(normalize_repo(repo))
            added += 1

    safe_existing.sort(key=lambda r: (r.get("created_at", ""), r.get("full_name", "")))
    print(f"[+] Added {added} new PoC repositories")
    return safe_existing


# ---------- discovery (year -> CVE queue) ----------

def extract_cves_from_repo(repo: dict, year: str) -> set[str]:
    cves: set[str] = set()

    full_name = repo.get("full_name") or ""
    name = repo.get("name") or ""
    desc = repo.get("description") or ""
    homepage = repo.get("homepage") or ""

    for text in (full_name, name, desc, homepage):
        for m in CVE_RE.finditer(text):
            if m.group(1) == year:
                cves.add(normalize_cve(year, m.group(2)))

    for t in repo.get("topics", []) or []:
        for m in CVE_RE.finditer(str(t)):
            if m.group(1) == year:
                cves.add(normalize_cve(year, m.group(2)))

    return cves


def _make_discovery_shards(shards: int) -> list[str]:
    """
    Flexible shard prefixes generator.
    - shards <= 10: "0".."shards-1"
    - shards > 10: zero-padded "00".."shards-1" (width grows as needed)
    Safety cap: 1..1000
    """
    shards = int(shards)
    shards = max(1, min(shards, 1000))

    if shards <= 10:
        return [str(i) for i in range(shards)]

    width = len(str(shards - 1))
    return [f"{i:0{width}d}" for i in range(shards)]


def discover_year_to_queue(
    token: str,
    year: str,
    pages: int,
    out_path: Path,
    shards: int = 10,
    *,
    throttle_seconds: float = DEFAULT_SEARCH_THROTTLE_SECONDS,
) -> None:
    pages = max(1, min(int(pages), 10))
    shard_prefixes = _make_discovery_shards(shards)

    all_cves: set[str] = set()
    total_repos = 0

    for prefix in shard_prefixes:
        query = f"CVE-{year}-{prefix} in:name,description,readme"
        shard_repos = 0
        shard_cves_before = len(all_cves)

        for p in range(1, pages + 1):
            repos = search_repos(token, query=query, per_page=100, page=p, throttle_seconds=throttle_seconds)
            if not repos:
                break

            shard_repos += len(repos)
            total_repos += len(repos)

            for repo in repos:
                all_cves |= extract_cves_from_repo(repo, year)

            print(f"[+] discover {year} shard {prefix}: page {p} -> repos={len(repos)} cves_total={len(all_cves)}")

        shard_added = len(all_cves) - shard_cves_before
        print(f"[+] shard {prefix} done: repos_scanned={shard_repos} new_cves={shard_added}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(sorted(all_cves)) + "\n", encoding="utf-8")
    print(f"[+] Saved queue: {out_path} (cves={len(all_cves)} repos_scanned={total_repos} shards={shards})")


# ---------- main ----------

def main() -> None:
    ap = argparse.ArgumentParser()

    ap.add_argument("--selftest", action="store_true", help="Show GitHub API rate limit info")

    ap.add_argument("--cve", help="Process single CVE, e.g. CVE-2017-0144")
    ap.add_argument("--cve-pages", type=int, default=3,
                    help="How many search pages to scan per query for a single CVE (100 repos/page). Default: 3 (max 10)")
    ap.add_argument("--no-readme-verify", action="store_true",
                    help="Disable README verification for in:readme results (fewer API calls)")

    ap.add_argument("--discover-year", help="Discover CVEs for a given year from GitHub, e.g. 2017")
    ap.add_argument("--discover-pages", type=int, default=5,
                    help="How many search pages to scan per shard (100 repos/page). Default: 5 (max 10)")
    ap.add_argument("--discover-shards", type=int, default=10,
                    help="Discovery shard count. Default 10. Use 50, 100, etc. Higher = better coverage, slower.")
    ap.add_argument("--throttle-seconds", type=float, default=DEFAULT_SEARCH_THROTTLE_SECONDS,
                    help="Sleep before each GitHub Search request. Default 2.2s. Increase if you still hit limits.")

    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN", "")
    ensure_token(token)

    if args.selftest:
        data = gh_get_json(f"{GITHUB_API}/rate_limit", token)
        print(json.dumps(data, indent=2))
        return

    if args.discover_year:
        year = str(args.discover_year).strip()
        if not re.fullmatch(r"\d{4}", year):
            print("ERROR: --discover-year must be YYYY", file=sys.stderr)
            sys.exit(1)

        out_path = ROOT / "tools" / f"queue_{year}.txt"
        discover_year_to_queue(
            token,
            year=year,
            pages=max(1, args.discover_pages),
            out_path=out_path,
            shards=args.discover_shards,
            throttle_seconds=max(0.0, float(args.throttle_seconds)),
        )
        return

    if not args.cve:
        print("ERROR: --cve is required (or use --discover-year)", file=sys.stderr)
        sys.exit(1)

    cve = args.cve.upper().strip()
    print(f"[+] Searching PoC for {cve}")

    found = search_repos_for_cve(
        token,
        cve,
        pages=args.cve_pages,
        verify_readme=(not args.no_readme_verify),
        throttle_seconds=max(0.0, float(args.throttle_seconds)),
    )

    path = cve_path(cve)
    existing = load_existing(path)
    merged = merge(existing, found)
    save(path, merged)
    print(f"[+] Saved {len(merged)} entries → {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
