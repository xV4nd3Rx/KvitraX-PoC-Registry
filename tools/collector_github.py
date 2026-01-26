#!/usr/bin/env python3
import os
import sys
import json
import re
import argparse
from datetime import datetime, timezone
from pathlib import Path

import requests

GITHUB_API = "https://api.github.com"
ROOT = Path(__file__).resolve().parent.parent

EXCLUDE_FULL_NAMES = {
    "nomi-sec/PoC-in-GitHub",
    "LulzSecToolkit/Lulz4Life",
}

# Allow 3+ digits after year (e.g. CVE-2026-666) and normalize queue to 4 digits (0666)
CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{3,})\b", re.IGNORECASE)


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


# ---------- GitHub search helpers ----------

def cve_search_variants(cve: str) -> list[str]:
    """
    Return CVE variants for search.
    Example: CVE-2026-0666 -> ["CVE-2026-0666", "CVE-2026-666"]
    """
    cve = cve.upper().strip()
    parts = cve.split("-")
    if len(parts) != 3:
        return [cve]

    year = parts[1]
    seq = parts[2]

    variants = [f"CVE-{year}-{seq}"]

    # If sequence has leading zeros, also search for non-padded form
    seq_unpadded = seq.lstrip("0") or "0"
    if seq_unpadded != seq:
        variants.append(f"CVE-{year}-{seq_unpadded}")

    # Deduplicate while preserving order
    out: list[str] = []
    seen: set[str] = set()
    for v in variants:
        if v not in seen:
            out.append(v)
            seen.add(v)
    return out


def repo_mentions_any_variant(repo: dict, variants: list[str]) -> bool:
    """
    Hard post-filter: keep only repos that mention exact CVE variant
    in repository metadata (name/full_name/description/topics).
    This blocks Search API noise from polluting JSON.
    """
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


def search_repos(token: str, query: str, per_page: int = 100, page: int = 1) -> list[dict]:
    """
    Generic GitHub repository search (paged).
    Used by discovery mode (--discover-year).
    """
    url = f"{GITHUB_API}/search/repositories"
    params = {
        "q": query,
        "per_page": per_page,
        "page": page,
        "sort": "indexed",
        "order": "desc",
    }

    r = gh_get(url, token, params=params)

    # Graceful stop for workflows if Search API rate limit hits
    if r.status_code == 403 and "rate limit" in r.text.lower():
        print(f"[!] Rate limit hit on query: {query}", file=sys.stderr)
        print(r.text, file=sys.stderr)
        sys.exit(3)

    if r.status_code != 200:
        raise RuntimeError(f"GitHub search failed: {r.status_code} {r.text}")

    items = r.json().get("items", [])

    # Filter known noisy repos
    filtered = [repo for repo in items if repo.get("full_name") not in EXCLUDE_FULL_NAMES]
    if len(items) != len(filtered):
        print(f"[!] Filtered out {len(items) - len(filtered)} aggregator repos")

    return filtered


def search_repos_for_cve(token: str, cve: str) -> list[dict]:
    """
    Strategy:
    - 1 request: (CVE-YYYY-0666 OR CVE-YYYY-666) in:name
    - fallback 1 request: ( ... ) in:name,description,readme
    Additionally applies a hard post-filter: CVE must be present in repo metadata.
    """
    variants = cve_search_variants(cve)

    # Build a single OR query for all variants
    if len(variants) == 1:
        or_part = variants[0]
    else:
        or_part = "(" + " OR ".join(variants) + ")"

    seen_ids: set[int] = set()
    all_items: list[dict] = []

    # 1) Tight: name-only
    items = search_repos(token, query=f"{or_part} in:name", per_page=100, page=1)
    before = len(items)
    items = [r for r in items if repo_mentions_any_variant(r, variants)]
    if before != len(items):
        print(f"[!] Post-filter kept {len(items)}/{before} repos after exact CVE check (name-only)")

    for repo in items:
        rid = repo.get("id")
        if isinstance(rid, int) and rid not in seen_ids:
            seen_ids.add(rid)
            all_items.append(repo)

    # 2) Fallback only if empty
    if not all_items:
        items = search_repos(token, query=f"{or_part} in:name,description,readme", per_page=100, page=1)
        before = len(items)
        items = [r for r in items if repo_mentions_any_variant(r, variants)]
        if before != len(items):
            print(f"[!] Post-filter kept {len(items)}/{before} repos after exact CVE check (fallback)")

        for repo in items:
            rid = repo.get("id")
            if isinstance(rid, int) and rid not in seen_ids:
                seen_ids.add(rid)
                all_items.append(repo)

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
        "visibility": repo["visibility"],
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


# ---------- discovery (year -> CVE list) ----------

def normalize_cve(year: str, seq: str) -> str:
    """
    Accepts seq with 3+ digits. If 3 digits, zero-pad to 4.
    Keeps 4+ as-is. Always uppercases.
    """
    seq = str(seq).strip()
    if len(seq) < 4:
        seq = seq.zfill(4)
    return f"CVE-{year}-{seq}".upper()


def extract_cves_from_repo(repo: dict, year: str) -> set[str]:
    cves: set[str] = set()

    full_name = repo.get("full_name") or ""
    name = repo.get("name") or ""
    desc = repo.get("description") or ""

    for text in (full_name, name, desc):
        for m in CVE_RE.finditer(text):
            if m.group(1) == year:
                cves.add(normalize_cve(year, m.group(2)))

    for t in repo.get("topics", []) or []:
        for m in CVE_RE.finditer(str(t)):
            if m.group(1) == year:
                cves.add(normalize_cve(year, m.group(2)))

    return cves


def discover_year_to_queue(token: str, year: str, pages: int, out_path: Path) -> None:
    # Discovery is inherently noisy; we accept it because we only extract CVE patterns from metadata.
    query = f"CVE-{year}- in:name,description,readme"

    all_cves: set[str] = set()
    total_repos = 0

    for page in range(1, pages + 1):
        repos = search_repos(token, query=query, per_page=100, page=page)
        if not repos:
            break

        total_repos += len(repos)

        for repo in repos:
            all_cves |= extract_cves_from_repo(repo, year)

        print(f"[+] discover {year}: page {page} -> repos={len(repos)} cves_total={len(all_cves)}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(sorted(all_cves)) + "\n", encoding="utf-8")

    print(f"[+] Saved queue: {out_path} (cves={len(all_cves)} repos_scanned={total_repos})")


# ---------- main ----------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--cve", help="Process single CVE, e.g. CVE-2026-22444")
    ap.add_argument("--discover-year", help="Discover CVEs for a given year from GitHub, e.g. 2026")
    ap.add_argument("--discover-pages", type=int, default=5,
                    help="How many search pages to scan (100 repos/page). Default: 5")
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN", "")
    ensure_token(token)

    if args.selftest:
        r = gh_get(f"{GITHUB_API}/rate_limit", token)
        print(json.dumps(r.json(), indent=2))
        return

    if args.discover_year:
        year = str(args.discover_year).strip()
        if not re.fullmatch(r"\d{4}", year):
            print("ERROR: --discover-year must be YYYY", file=sys.stderr)
            sys.exit(1)

        out_path = ROOT / "tools" / f"queue_{year}.txt"
        discover_year_to_queue(token, year=year, pages=max(1, args.discover_pages), out_path=out_path)
        return

    if not args.cve:
        print("ERROR: --cve is required (or use --discover-year)", file=sys.stderr)
        sys.exit(1)

    cve = args.cve.upper().strip()
    print(f"[+] Searching PoC for {cve}")

    found = search_repos_for_cve(token, cve)
    path = cve_path(cve)

    existing = load_existing(path)
    merged = merge(existing, found)
    save(path, merged)

    print(f"[+] Saved {len(merged)} entries → {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
