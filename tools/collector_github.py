#!/usr/bin/env python3
import os
import sys
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

import requests

GITHUB_API = "https://api.github.com"
ROOT = Path(__file__).resolve().parent.parent
EXCLUDE_FULL_NAMES = {
    "nomi-sec/PoC-in-GitHub",
    #"trickest/cve",                 # часто агрегатор
    #"vulncheck-oss/vulncheck-kev",  # примеры шумных баз (если всплывут)
}


# ---------- utils ----------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def gh_get(url: str, token: str, params: dict | None = None) -> requests.Response:
    return requests.get(url, headers=gh_headers(token), params=params, timeout=45)


# ---------- GitHub search ----------

def search_repos(token: str, cve: str) -> list[dict]:
    query = f"{cve} in:name,description,readme"
    url = f"{GITHUB_API}/search/repositories"

    params = {
        "q": query,
        "per_page": 100,
        "sort": "indexed",
        "order": "desc",
    }

    r = gh_get(url, token, params=params)
    if r.status_code != 200:
        raise RuntimeError(f"GitHub search failed: {r.status_code} {r.text}")

    items = r.json().get("items", [])

    # 🔥 фильтр агрегаторов / шума
    filtered = [
        repo for repo in items
        if repo.get("full_name") not in EXCLUDE_FULL_NAMES
    ]

    if len(items) != len(filtered):
        print(f"[!] Filtered out {len(items) - len(filtered)} aggregator repos")

    return filtered


# ---------- filesystem ----------

def cve_path(cve: str) -> Path:
    year = cve.split("-")[1]
    return ROOT / year / f"{cve}.json"


def load_existing(path: Path) -> list[dict]:
    """
    Accepts:
    - []                              (nomi-sec style)
    - { "entries": [] }
    - { "items": [] }
    - { "repos": [] }
    - single repo object { id, full_name, ... }
    """
    if not path.exists():
        return []

    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in {path}: {e}")

    # 1) nomi-sec style
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]

    # 2) object containers
    if isinstance(data, dict):
        for key in ("entries", "items", "repos", "repositories"):
            if isinstance(data.get(key), list):
                return [x for x in data[key] if isinstance(x, dict)]

        # 3) single repo object
        if "id" in data and "full_name" in data:
            return [data]

        raise RuntimeError(
            f"Unsupported JSON object in {path}. Keys: {list(data.keys())}"
        )

    raise RuntimeError(f"Unsupported JSON root type in {path}: {type(data).__name__}")


def save(path: Path, data: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


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
        "visibility": repo["visibility"],
    }


def merge(existing: list[dict], found: list[dict]) -> list[dict]:
    safe_existing = [e for e in existing if isinstance(e, dict) and "id" in e]
    known_ids = {e["id"] for e in safe_existing}

    added = 0
    for repo in found:
        if repo["id"] not in known_ids:
            safe_existing.append(normalize_repo(repo))
            added += 1

    safe_existing.sort(key=lambda r: (r.get("created_at", ""), r.get("full_name", "")))
    print(f"[+] Added {added} new PoC repositories")

    return safe_existing


# ---------- main ----------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--cve", help="Process single CVE, e.g. CVE-2026-22444")
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN", "")
    ensure_token(token)

    if args.selftest:
        r = gh_get(f"{GITHUB_API}/rate_limit", token)
        print(json.dumps(r.json(), indent=2))
        return

    if not args.cve:
        print("ERROR: --cve is required", file=sys.stderr)
        sys.exit(1)

    cve = args.cve.upper()
    print(f"[+] Searching PoC for {cve}")

    found = search_repos(token, cve)
    path = cve_path(cve)

    existing = load_existing(path)
    merged = merge(existing, found)
    save(path, merged)

    print(f"[+] Saved {len(merged)} entries → {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

