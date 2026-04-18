"""Local-first threat intel: CVE metadata, CISA-KEV, EPSS, CWE.

Why local-first:

  - Operators triage on a plane, in a SCIF, in a client DMZ — anywhere
    an outbound HTTPS call is either slow, blocked, or logged. Triage
    needs to work offline.
  - The public feeds are small enough to keep entirely in SQLite
    (~50 MB compressed). Query latency is microseconds once synced.

Design:

  - Single SQLite DB at <KODA_HOME>/intel/intel.db (WAL).
  - One table per feed, plus a ``meta`` table recording last-sync time.
  - Sync is atomic per table: download to memory, TRUNCATE + bulk insert
    inside a transaction. If the download fails mid-stream, the old
    data stays intact.
  - No third-party deps. Pure stdlib (urllib, gzip, zipfile, csv, xml).

Public feeds (all free):
  - CISA KEV  : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - EPSS      : https://epss.cyentia.com/epss_scores-current.csv.gz
  - CWE       : https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
  - NVD feeds : yearly JSON gz mirrors (optional; large, so off by default)
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

_USER_AGENT = "K.O.D.A./intel-sync (github.com/vektra/koda)"
_DOWNLOAD_TIMEOUT = 90
_DOWNLOAD_MAX_BYTES = 100 * 1024 * 1024  # 100 MB cap per feed


@dataclass(frozen=True)
class KEVInfo:
    cve_id: str
    vendor: str = ""
    product: str = ""
    name: str = ""
    date_added: str = ""
    short_description: str = ""
    required_action: str = ""
    due_date: str = ""
    known_ransomware: bool = False


@dataclass(frozen=True)
class EPSSInfo:
    cve_id: str
    score: float = 0.0
    percentile: float = 0.0
    as_of: str = ""


@dataclass(frozen=True)
class CVEInfo:
    cve_id: str
    description: str = ""
    cvss_v3_score: float = 0.0
    cvss_v3_vector: str = ""
    cwe_ids: tuple[str, ...] = ()
    published_at: str = ""
    last_modified: str = ""


@dataclass(frozen=True)
class CWEInfo:
    cwe_id: str
    name: str = ""
    description: str = ""
    url: str = ""


@dataclass
class EnrichmentBundle:
    cve_id: str
    cve: CVEInfo | None = None
    kev: KEVInfo | None = None
    epss: EPSSInfo | None = None
    cwes: list[CWEInfo] = field(default_factory=list)

    def exploitability_score(self) -> float:
        """Heuristic 0-100 blend: KEV > EPSS > CVSS.

        KEV hit pins the floor high because it means active exploitation.
        EPSS adds predictive signal. CVSS is the tiebreaker.
        """
        score = 0.0
        if self.kev:
            score = max(score, 85.0)
            if self.kev.known_ransomware:
                score = max(score, 95.0)
        if self.epss:
            score = max(score, float(self.epss.percentile) * 100.0)
        if self.cve:
            score = max(score, float(self.cve.cvss_v3_score) * 10.0)
        return min(100.0, round(score, 2))


@dataclass
class Freshness:
    kev_last_sync: str = ""
    epss_last_sync: str = ""
    cwe_last_sync: str = ""
    nvd_last_sync: str = ""
    counts: dict[str, int] = field(default_factory=dict)


def default_intel_path() -> Path:
    root = Path(os.environ.get("KODA_HOME", str(Path.home() / ".koda")))
    return root / "intel"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS kev (
    cve_id             TEXT PRIMARY KEY,
    vendor             TEXT NOT NULL DEFAULT '',
    product            TEXT NOT NULL DEFAULT '',
    name               TEXT NOT NULL DEFAULT '',
    date_added         TEXT NOT NULL DEFAULT '',
    short_description  TEXT NOT NULL DEFAULT '',
    required_action    TEXT NOT NULL DEFAULT '',
    due_date           TEXT NOT NULL DEFAULT '',
    known_ransomware   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS epss (
    cve_id     TEXT PRIMARY KEY,
    score      REAL NOT NULL DEFAULT 0.0,
    percentile REAL NOT NULL DEFAULT 0.0,
    as_of      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS epss_percentile ON epss(percentile DESC);
CREATE TABLE IF NOT EXISTS cves (
    cve_id         TEXT PRIMARY KEY,
    description    TEXT NOT NULL DEFAULT '',
    cvss_v3_score  REAL NOT NULL DEFAULT 0.0,
    cvss_v3_vector TEXT NOT NULL DEFAULT '',
    cwe_ids        TEXT NOT NULL DEFAULT '[]',
    published_at   TEXT NOT NULL DEFAULT '',
    last_modified  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS cwes (
    cwe_id      TEXT PRIMARY KEY,
    name        TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    url         TEXT NOT NULL DEFAULT ''
);
"""


class NullThreatIntel:
    """No-op. Enrichment calls return empty bundles."""

    def enrich(self, cve_ids: Iterable[str]) -> dict[str, EnrichmentBundle]:
        return {cid: EnrichmentBundle(cve_id=cid) for cid in cve_ids}

    def lookup_cve(self, cve_id: str) -> EnrichmentBundle:
        return EnrichmentBundle(cve_id=cve_id)

    def freshness(self) -> Freshness:
        return Freshness()

    def sync(self, **_: Any) -> dict[str, str]:
        return {"status": "disabled"}

    def close(self) -> None:
        return None


class ThreatIntel:
    """Local SQLite-backed threat intel cache."""

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        audit: Any = None,
    ) -> None:
        self.root = Path(path) if path else default_intel_path()
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "intel.db"
        self.audit = audit
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._ensure_open()

    def _ensure_open(self) -> None:
        if self._conn is not None:
            return
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(_SCHEMA)
        self._conn = conn

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.commit()
                    self._conn.close()
                finally:
                    self._conn = None

    def _emit(self, event: str, **fields: Any) -> None:
        if self.audit is None:
            return
        try:
            self.audit.emit(event, **fields)
        except Exception:
            pass

    # --- enrichment / queries ---

    def lookup_cve(self, cve_id: str) -> EnrichmentBundle:
        cve_id = (cve_id or "").strip().upper()
        if not cve_id:
            return EnrichmentBundle(cve_id="")

        with self._lock:
            self._ensure_open()
            assert self._conn is not None
            cve_row = self._conn.execute(
                "SELECT * FROM cves WHERE cve_id=?", (cve_id,)
            ).fetchone()
            kev_row = self._conn.execute(
                "SELECT * FROM kev WHERE cve_id=?", (cve_id,)
            ).fetchone()
            epss_row = self._conn.execute(
                "SELECT * FROM epss WHERE cve_id=?", (cve_id,)
            ).fetchone()
            cwe_rows: list[sqlite3.Row] = []
            if cve_row is not None:
                try:
                    cwe_ids = json.loads(cve_row["cwe_ids"] or "[]")
                except (TypeError, ValueError):
                    cwe_ids = []
                for cwe_id in cwe_ids:
                    row = self._conn.execute(
                        "SELECT * FROM cwes WHERE cwe_id=?", (cwe_id,)
                    ).fetchone()
                    if row is not None:
                        cwe_rows.append(row)

        bundle = EnrichmentBundle(cve_id=cve_id)
        if cve_row is not None:
            try:
                cwe_ids = tuple(json.loads(cve_row["cwe_ids"] or "[]"))
            except (TypeError, ValueError):
                cwe_ids = ()
            bundle.cve = CVEInfo(
                cve_id=cve_row["cve_id"],
                description=cve_row["description"] or "",
                cvss_v3_score=float(cve_row["cvss_v3_score"] or 0.0),
                cvss_v3_vector=cve_row["cvss_v3_vector"] or "",
                cwe_ids=cwe_ids,
                published_at=cve_row["published_at"] or "",
                last_modified=cve_row["last_modified"] or "",
            )
        if kev_row is not None:
            bundle.kev = KEVInfo(
                cve_id=kev_row["cve_id"],
                vendor=kev_row["vendor"] or "",
                product=kev_row["product"] or "",
                name=kev_row["name"] or "",
                date_added=kev_row["date_added"] or "",
                short_description=kev_row["short_description"] or "",
                required_action=kev_row["required_action"] or "",
                due_date=kev_row["due_date"] or "",
                known_ransomware=bool(kev_row["known_ransomware"]),
            )
        if epss_row is not None:
            bundle.epss = EPSSInfo(
                cve_id=epss_row["cve_id"],
                score=float(epss_row["score"] or 0.0),
                percentile=float(epss_row["percentile"] or 0.0),
                as_of=epss_row["as_of"] or "",
            )
        for row in cwe_rows:
            bundle.cwes.append(
                CWEInfo(
                    cwe_id=row["cwe_id"],
                    name=row["name"] or "",
                    description=row["description"] or "",
                    url=row["url"] or "",
                )
            )
        return bundle

    def enrich(self, cve_ids: Iterable[str]) -> dict[str, EnrichmentBundle]:
        out: dict[str, EnrichmentBundle] = {}
        for cid in cve_ids:
            cid = (cid or "").strip().upper()
            if cid and cid not in out:
                out[cid] = self.lookup_cve(cid)
        return out

    def freshness(self) -> Freshness:
        with self._lock:
            self._ensure_open()
            assert self._conn is not None
            meta = dict(self._conn.execute("SELECT key, value FROM meta").fetchall())
            counts = {
                "cves": self._conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0],
                "kev": self._conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0],
                "epss": self._conn.execute("SELECT COUNT(*) FROM epss").fetchone()[0],
                "cwes": self._conn.execute("SELECT COUNT(*) FROM cwes").fetchone()[0],
            }
        return Freshness(
            kev_last_sync=meta.get("kev_last_sync") or "",
            epss_last_sync=meta.get("epss_last_sync") or "",
            cwe_last_sync=meta.get("cwe_last_sync") or "",
            nvd_last_sync=meta.get("nvd_last_sync") or "",
            counts=counts,
        )

    # --- sync ---

    def sync(
        self,
        *,
        kev: bool = True,
        epss: bool = True,
        cwe: bool = False,
    ) -> dict[str, str]:
        status: dict[str, str] = {}
        if kev:
            status["kev"] = self._sync_kev()
        if epss:
            status["epss"] = self._sync_epss()
        if cwe:
            status["cwe"] = self._sync_cwe()
        return status

    def _download(self, url: str) -> bytes:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, timeout=_DOWNLOAD_TIMEOUT) as resp:
            buf = io.BytesIO()
            read = 0
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                read += len(chunk)
                if read > _DOWNLOAD_MAX_BYTES:
                    raise IOError(f"feed exceeded {_DOWNLOAD_MAX_BYTES} bytes: {url}")
                buf.write(chunk)
            return buf.getvalue()

    def _record_sync(self, feed: str, iso: str, row_count: int) -> None:
        assert self._conn is not None
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (f"{feed}_last_sync", iso),
        )
        self._emit("intel.sync", feed=feed, rows=row_count, at=iso)

    def _sync_kev(self) -> str:
        try:
            raw = self._download(_KEV_URL)
            data = json.loads(raw.decode("utf-8"))
            vulns = data.get("vulnerabilities") or []
        except (urllib.error.URLError, IOError, json.JSONDecodeError) as exc:
            return f"error: {exc}"

        iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"
        with self._lock:
            self._ensure_open()
            assert self._conn is not None
            try:
                with self._conn:
                    self._conn.execute("DELETE FROM kev")
                    self._conn.executemany(
                        "INSERT INTO kev(cve_id, vendor, product, name, date_added,"
                        " short_description, required_action, due_date, known_ransomware)"
                        " VALUES(?,?,?,?,?,?,?,?,?)",
                        [
                            (
                                (v.get("cveID") or "").upper(),
                                v.get("vendorProject") or "",
                                v.get("product") or "",
                                v.get("vulnerabilityName") or "",
                                v.get("dateAdded") or "",
                                v.get("shortDescription") or "",
                                v.get("requiredAction") or "",
                                v.get("dueDate") or "",
                                1 if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known" else 0,
                            )
                            for v in vulns
                        ],
                    )
                    self._record_sync("kev", iso, len(vulns))
            except sqlite3.Error as exc:
                return f"db error: {exc}"
        return f"ok: {len(vulns)} rows"

    def _sync_epss(self) -> str:
        try:
            raw = self._download(_EPSS_URL)
            text = gzip.decompress(raw).decode("utf-8", errors="replace")
        except (urllib.error.URLError, IOError, OSError) as exc:
            return f"error: {exc}"

        reader = csv.reader(io.StringIO(text))
        rows: list[tuple[str, float, float, str]] = []
        as_of = ""
        score_idx = percentile_idx = cve_idx = -1
        headers_seen = False
        for line in reader:
            if not line:
                continue
            # Comment lines start with "#" and may embed a score_date:
            #   #model_version:v2024.06.25,score_date:2024-06-25T00:00:00+0000
            if line[0].startswith("#"):
                joined = ",".join(line)
                if "score_date:" in joined:
                    as_of = joined.split("score_date:", 1)[1].split(",", 1)[0]
                continue
            if not headers_seen:
                headers = [c.strip().lower() for c in line]
                try:
                    cve_idx = headers.index("cve")
                    score_idx = headers.index("epss")
                    percentile_idx = headers.index("percentile")
                except ValueError:
                    return "error: EPSS header layout changed"
                headers_seen = True
                continue
            if len(line) <= max(cve_idx, score_idx, percentile_idx):
                continue
            try:
                rows.append(
                    (
                        line[cve_idx].strip().upper(),
                        float(line[score_idx] or 0.0),
                        float(line[percentile_idx] or 0.0),
                        as_of,
                    )
                )
            except ValueError:
                continue

        iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"
        with self._lock:
            self._ensure_open()
            assert self._conn is not None
            try:
                with self._conn:
                    self._conn.execute("DELETE FROM epss")
                    self._conn.executemany(
                        "INSERT INTO epss(cve_id, score, percentile, as_of)"
                        " VALUES(?,?,?,?)",
                        rows,
                    )
                    self._record_sync("epss", iso, len(rows))
            except sqlite3.Error as exc:
                return f"db error: {exc}"
        return f"ok: {len(rows)} rows"

    def _sync_cwe(self) -> str:
        try:
            raw = self._download(_CWE_URL)
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                xml_names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
                if not xml_names:
                    return "error: no xml in CWE bundle"
                xml_bytes = zf.read(xml_names[0])
        except (urllib.error.URLError, IOError, zipfile.BadZipFile) as exc:
            return f"error: {exc}"

        try:
            tree = ET.parse(io.BytesIO(xml_bytes))
        except ET.ParseError as exc:
            return f"xml error: {exc}"

        ns = {"c": "http://cwe.mitre.org/cwe-7"}
        rows: list[tuple[str, str, str, str]] = []
        root = tree.getroot()
        for weakness in root.iter("{http://cwe.mitre.org/cwe-7}Weakness"):
            cwe_id = f"CWE-{weakness.get('ID', '').strip()}"
            name = weakness.get("Name", "") or ""
            desc_el = weakness.find("c:Description", ns)
            desc = (desc_el.text or "").strip() if desc_el is not None else ""
            url = f"https://cwe.mitre.org/data/definitions/{weakness.get('ID', '')}.html"
            rows.append((cwe_id, name, desc, url))

        iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"
        with self._lock:
            self._ensure_open()
            assert self._conn is not None
            try:
                with self._conn:
                    self._conn.execute("DELETE FROM cwes")
                    self._conn.executemany(
                        "INSERT INTO cwes(cwe_id, name, description, url)"
                        " VALUES(?,?,?,?)",
                        rows,
                    )
                    self._record_sync("cwe", iso, len(rows))
            except sqlite3.Error as exc:
                return f"db error: {exc}"
        return f"ok: {len(rows)} rows"

    # --- CVE ingest (called by operators who have their own NVD mirror) ---

    def upsert_cves(self, records: Iterable[dict[str, Any]]) -> int:
        """Bulk upsert CVE rows. Records are plain dicts with keys matching
        the CVEInfo dataclass. Lets operators feed their own NVD snapshots
        without us shipping a 300 MB download path."""
        count = 0
        with self._lock:
            self._ensure_open()
            assert self._conn is not None
            with self._conn:
                for rec in records:
                    cve_id = (rec.get("cve_id") or "").strip().upper()
                    if not cve_id:
                        continue
                    cwe_ids = list(rec.get("cwe_ids") or [])
                    self._conn.execute(
                        "INSERT INTO cves(cve_id, description, cvss_v3_score,"
                        " cvss_v3_vector, cwe_ids, published_at, last_modified)"
                        " VALUES(?,?,?,?,?,?,?)"
                        " ON CONFLICT(cve_id) DO UPDATE SET"
                        " description=excluded.description,"
                        " cvss_v3_score=excluded.cvss_v3_score,"
                        " cvss_v3_vector=excluded.cvss_v3_vector,"
                        " cwe_ids=excluded.cwe_ids,"
                        " last_modified=excluded.last_modified",
                        (
                            cve_id,
                            rec.get("description") or "",
                            float(rec.get("cvss_v3_score") or 0.0),
                            rec.get("cvss_v3_vector") or "",
                            json.dumps(cwe_ids),
                            rec.get("published_at") or "",
                            rec.get("last_modified") or "",
                        ),
                    )
                    count += 1
                if count:
                    iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"
                    self._record_sync("nvd", iso, count)
        return count


__all__ = [
    "CVEInfo",
    "CWEInfo",
    "EPSSInfo",
    "EnrichmentBundle",
    "Freshness",
    "KEVInfo",
    "NullThreatIntel",
    "ThreatIntel",
    "default_intel_path",
]
