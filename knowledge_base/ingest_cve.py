#!/usr/bin/env python3
"""
Ingest NVD CVE data into ChromaDB collection 'cve_database'.
NVD API 2.0 — max 120-day window per request, so we fetch monthly.
"""
import hashlib, json, sys, time
from pathlib import Path
from datetime import datetime, timedelta

import chromadb
import requests
from chromadb.config import Settings
from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn

ROOT        = Path(__file__).parent.parent
CHROMA_PATH = ROOT / "memory" / "chromadb"
CVE_DIR     = Path(__file__).parent / "cve"
COLLECTION  = "cve_database"
BATCH_SIZE  = 200
NVD_API     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE   = 500   # conservative for reliability
SLEEP       = 7     # NVD rate limit: 5 req/30s without API key

console = Console()


def monthly_ranges(years: list[int]) -> list[tuple[str, str, str]]:
    """Generate monthly date ranges as (start, end, label)."""
    ranges = []
    for year in years:
        for month in range(1, 13):
            start = datetime(year, month, 1)
            if month == 12:
                end = datetime(year, 12, 31, 23, 59, 59)
            else:
                end = datetime(year, month + 1, 1) - timedelta(seconds=1)
            if end > datetime.now():
                break
            ranges.append((
                start.strftime("%Y-%m-%dT%H:%M:%S"),
                end.strftime("%Y-%m-%dT%H:%M:%S"),
                f"{year}-{month:02d}",
            ))
    return ranges


def make_url(start: str, end: str, index: int) -> str:
    return (f"{NVD_API}?pubStartDate={start}&pubEndDate={end}"
            f"&resultsPerPage={PAGE_SIZE}&startIndex={index}")


def get_page(session: requests.Session, url: str) -> dict | None:
    for attempt in range(2):
        try:
            r = session.get(url, timeout=30)
            if r.status_code == 404:
                console.print(f"[yellow]  404 for {url[:80]}...[/]")
                return None
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if attempt == 0:
                console.print(f"[yellow]  Retry ({type(e).__name__})[/]")
                time.sleep(SLEEP)
            else:
                console.print(f"[red]  ✗ {e}[/]")
                return None


def fetch_months(years: list[int]) -> list[dict]:
    all_vulns: list[dict] = []
    session = requests.Session()
    session.headers["User-Agent"] = "CyberAgent/1.0"
    ranges = monthly_ranges(years)

    for start, end, label in ranges:
        cache = CVE_DIR / f"nvd_{label}.json"
        if cache.exists() and cache.stat().st_size > 1_000:
            data = json.loads(cache.read_text())
            all_vulns.extend(data)
            console.print(f"[yellow]  ⏭ {label}: {len(data)} cached[/]")
            continue

        data = get_page(session, make_url(start, end, 0))
        if not data:
            continue
        total   = data.get("totalResults", 0)
        vulns   = list(data.get("vulnerabilities", []))
        console.print(f"[dim]  {label}: {total} CVEs[/]")

        idx = PAGE_SIZE
        while idx < total:
            time.sleep(SLEEP)
            page = get_page(session, make_url(start, end, idx))
            if page:
                vulns.extend(page.get("vulnerabilities", []))
            idx += PAGE_SIZE

        CVE_DIR.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(vulns))
        all_vulns.extend(vulns)
        time.sleep(SLEEP)

    return all_vulns


def parse_vuln(vuln: dict) -> dict | None:
    cve    = vuln.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None
    descs = cve.get("descriptions", [])
    desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")[:1500]
    metrics = cve.get("metrics", {})
    cvss, sev = "0.0", "UNKNOWN"
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m    = metrics[key][0].get("cvssData", {})
            cvss = str(m.get("baseScore", "0.0"))
            sev  = m.get("baseSeverity", m.get("accessVector", "UNKNOWN"))
            break
    products: set[str] = set()
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                p = cm.get("criteria", "").split(":")
                if len(p) > 4:
                    products.add(f"{p[3]}:{p[4]}")
    refs = [r.get("url", "") for r in cve.get("references", [])[:3]]
    return {
        "cve_id":            cve_id,
        "description":       desc,
        "cvss_v3":           cvss,
        "severity":          str(sev),
        "affected_products": ", ".join(list(products)[:10])[:400],
        "references":        ", ".join(refs)[:400],
        "published":         cve.get("published", "")[:10],
    }


def build_document(c: dict) -> str:
    return (f"CVE ID: {c['cve_id']}\nDescription: {c['description']}\n"
            f"CVSS v3: {c['cvss_v3']} ({c['severity']})\n"
            f"Affected: {c['affected_products']}\nPublished: {c['published']}")


def ingest_cve(skip_if_populated: bool = True) -> int:
    CHROMA_PATH.mkdir(parents=True, exist_ok=True)
    CVE_DIR.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(CHROMA_PATH),
                                       settings=Settings(anonymized_telemetry=False))
    col = client.get_or_create_collection(COLLECTION, metadata={"hnsw:space": "cosine"})

    if skip_if_populated and col.count() > 0:
        console.print(f"[yellow]⏭ cve_database[/] already has {col.count():,} docs — skipping.")
        return 0

    console.print("[cyan]→ Fetching CVEs (2023–2024) in monthly chunks...[/]")
    all_vulns = fetch_months([2023, 2024])
    parsed    = [p for v in all_vulns if (p := parse_vuln(v))]

    if not parsed:
        console.print("[red]✗ No CVE data — skipping[/]"); return 0

    console.print(f"[cyan]→ {len(parsed):,} CVEs — ingesting into ChromaDB...[/]")
    ids, docs, metas, inserted, seen = [], [], [], 0, set()

    with Progress(TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TaskProgressColumn(), console=console) as prog:
        task = prog.add_task("Ingesting cve_database", total=len(parsed))
        for c in parsed:
            did = hashlib.md5(f"cve:{c['cve_id']}".encode()).hexdigest()
            if did in seen: prog.advance(task); continue
            seen.add(did)
            ids.append(did); docs.append(build_document(c))
            metas.append({"cve_id": c["cve_id"], "cvss_v3": c["cvss_v3"],
                           "severity": c["severity"],
                           "affected_products": c["affected_products"][:400],
                           "published": c["published"]})
            if len(ids) >= BATCH_SIZE:
                col.add(ids=ids, documents=docs, metadatas=metas)
                inserted += len(ids); ids, docs, metas = [], [], []
            prog.advance(task)
        if ids:
            col.add(ids=ids, documents=docs, metadatas=metas); inserted += len(ids)

    console.print(f"[green]✓ cve_database[/] — {inserted:,} CVEs ingested.")
    return inserted


if __name__ == "__main__":
    ingest_cve(skip_if_populated="--force" not in sys.argv)
