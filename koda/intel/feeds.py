"""Extended threat-intel feeds: full NVD, ExploitDB, MITRE ATT&CK, CAPEC.

Layers on top of ``koda.intel.store.ThreatIntel`` without touching its core
schema. Adds CREATE-TABLE-IF-NOT-EXISTS migrations and atomic sync
functions for four additional public feeds:

  - NVD (full CVE corpus)   : CVEProject/cvelistV5 on GitHub, streamed via tar
  - ExploitDB               : exploit-database/exploitdb on GitLab
  - MITRE ATT&CK Enterprise : mitre/cti on GitHub (STIX 2.x bundle)
  - CAPEC                   : capec.mitre.org XML feed

All sync functions are defensive: network / parse / DB failures return
``'error: <detail>'`` strings and never raise. Writes are atomic — each
feed is DELETE+INSERT inside a single transaction, so a mid-sync failure
leaves the previous snapshot intact.

Pure stdlib. No third-party deps.
"""
from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
import sys
import tarfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any

_NVD_TARBALL_URL = (
    "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.tar.gz"
)
_EXPLOITDB_CSV_URL = (
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
)
_ATTACK_JSON_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
_CAPEC_XML_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"

_USER_AGENT = "K.O.D.A./intel-sync (github.com/vektra/koda)"
_STREAM_TIMEOUT = 600  # large NVD tarball can take minutes

_CVE_FILE_RE = re.compile(r"cves/\d{4}/\d+xxx/CVE-\d+-\d+\.json$")
_CWE_RE = re.compile(r"^CWE-\d+$")

_CAPEC_NS = {"c": "http://capec.mitre.org/capec-3"}


@dataclass(frozen=True)
class ExploitInfo:
    edb_id: str
    file_path: str = ""
    description: str = ""
    date_published: str = ""
    author: str = ""
    platform: str = ""
    type: str = ""
    verified: bool = False
    cve_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class AttackTechnique:
    technique_id: str
    name: str = ""
    description: str = ""
    tactic: str = ""
    url: str = ""
    is_subtechnique: bool = False
    parent_id: str = ""


@dataclass(frozen=True)
class AttackTactic:
    tactic_id: str
    name: str = ""
    description: str = ""
    url: str = ""


@dataclass(frozen=True)
class CapecInfo:
    capec_id: str
    name: str = ""
    description: str = ""
    likelihood_of_attack: str = ""
    typical_severity: str = ""
    url: str = ""
    cwe_ids: tuple[str, ...] = ()


_EXTENDED_SCHEMA = """
CREATE TABLE IF NOT EXISTS exploits (
    edb_id          TEXT PRIMARY KEY,
    file_path       TEXT,
    description     TEXT,
    date_published  TEXT,
    author          TEXT,
    platform        TEXT,
    type            TEXT,
    verified        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS exploits_platform ON exploits(platform);
CREATE TABLE IF NOT EXISTS exploit_cve_map (
    edb_id TEXT,
    cve_id TEXT,
    PRIMARY KEY(edb_id, cve_id)
);
CREATE INDEX IF NOT EXISTS exploit_cve_map_cve ON exploit_cve_map(cve_id);
CREATE TABLE IF NOT EXISTS attack_tactics (
    tactic_id   TEXT PRIMARY KEY,
    name        TEXT,
    description TEXT,
    url         TEXT
);
CREATE TABLE IF NOT EXISTS attack_techniques (
    technique_id    TEXT PRIMARY KEY,
    name            TEXT,
    description     TEXT,
    tactic          TEXT,
    url             TEXT,
    is_subtechnique INTEGER NOT NULL DEFAULT 0,
    parent_id       TEXT
);
CREATE INDEX IF NOT EXISTS attack_techniques_parent ON attack_techniques(parent_id);
CREATE TABLE IF NOT EXISTS attack_technique_tactic_map (
    technique_id TEXT,
    tactic_id    TEXT,
    PRIMARY KEY(technique_id, tactic_id)
);
CREATE TABLE IF NOT EXISTS capec (
    capec_id             TEXT PRIMARY KEY,
    name                 TEXT,
    description          TEXT,
    likelihood_of_attack TEXT,
    typical_severity     TEXT,
    url                  TEXT
);
CREATE TABLE IF NOT EXISTS capec_cwe_map (
    capec_id TEXT,
    cwe_id   TEXT,
    PRIMARY KEY(capec_id, cwe_id)
);
"""


def register_extended_schema(conn: sqlite3.Connection) -> None:
    """Ensure the extended tables exist on ``conn``. Idempotent."""
    conn.executescript(_EXTENDED_SCHEMA)


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"


# ---------------------------------------------------------------------------
# NVD (full CVE corpus, streamed tarball)
# ---------------------------------------------------------------------------


def _extract_cve_record(data: dict[str, Any]) -> dict[str, Any] | None:
    meta = data.get("cveMetadata") or {}
    cve_id = (meta.get("cveId") or "").strip().upper()
    if not cve_id:
        return None
    if (meta.get("state") or "").upper() == "REJECTED":
        return None

    containers = data.get("containers") or {}
    cna = containers.get("cna") or {}

    description = ""
    descs = cna.get("descriptions") or []
    if isinstance(descs, list) and descs:
        en = next(
            (d for d in descs if isinstance(d, dict) and d.get("lang") == "en"),
            None,
        )
        picked = en if en is not None else (descs[0] if isinstance(descs[0], dict) else None)
        if picked is not None:
            description = picked.get("value") or ""

    cvss_score = 0.0
    cvss_vector = ""
    metrics = cna.get("metrics") or []
    if isinstance(metrics, list):
        # Prefer v3.1, then v3.0.
        for key in ("cvssV3_1", "cvssV3_0"):
            for m in metrics:
                if not isinstance(m, dict):
                    continue
                block = m.get(key)
                if isinstance(block, dict):
                    try:
                        cvss_score = float(block.get("baseScore") or 0.0)
                    except (TypeError, ValueError):
                        cvss_score = 0.0
                    cvss_vector = block.get("vectorString") or ""
                    break
            if cvss_vector or cvss_score:
                break

    cwe_ids: list[str] = []
    for pt in cna.get("problemTypes") or []:
        if not isinstance(pt, dict):
            continue
        for d in pt.get("descriptions") or []:
            if not isinstance(d, dict):
                continue
            raw = (d.get("cweId") or "").strip()
            if raw and _CWE_RE.match(raw) and raw not in cwe_ids:
                cwe_ids.append(raw)

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_v3_score": cvss_score,
        "cvss_v3_vector": cvss_vector,
        "cwe_ids": cwe_ids,
        "published_at": meta.get("datePublished") or "",
        "last_modified": meta.get("dateUpdated") or "",
    }


def sync_nvd(intel) -> str:
    """Full NVD sync via streamed cvelistV5 tarball. Batches upserts by 1000."""
    iso = _iso_now()
    batch: list[dict[str, Any]] = []
    count = 0
    try:
        req = urllib.request.Request(
            _NVD_TARBALL_URL, headers={"User-Agent": _USER_AGENT}
        )
        with urllib.request.urlopen(req, timeout=_STREAM_TIMEOUT) as resp:
            with tarfile.open(fileobj=resp, mode="r|gz") as tar:
                for member in tar:
                    if not member.isfile():
                        continue
                    name = member.name
                    if not _CVE_FILE_RE.search(name):
                        continue
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    try:
                        payload = f.read()
                    finally:
                        f.close()
                    try:
                        data = json.loads(payload.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    rec = _extract_cve_record(data)
                    if rec is None:
                        continue
                    batch.append(rec)
                    count += 1
                    if len(batch) >= 1000:
                        intel.upsert_cves(batch)
                        batch = []
                    if count % 5000 == 0:
                        print(f"[nvd] {count} CVEs ingested", file=sys.stderr)
        if batch:
            intel.upsert_cves(batch)
    except (
        OSError,
        urllib.error.URLError,
        urllib.error.HTTPError,
        json.JSONDecodeError,
        tarfile.TarError,
        sqlite3.Error,
        ValueError,
        KeyError,
    ) as exc:
        return f"error: {exc}"

    try:
        with intel._lock:
            intel._ensure_open()
            assert intel._conn is not None
            with intel._conn:
                intel._record_sync("nvd", iso, count)
    except sqlite3.Error as exc:
        return f"error: {exc}"

    return f"ok: {count} rows"


# ---------------------------------------------------------------------------
# ExploitDB
# ---------------------------------------------------------------------------


def sync_exploitdb(intel) -> str:
    try:
        raw = intel._download(_EXPLOITDB_CSV_URL)
        text = raw.decode("utf-8", errors="replace")
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        return f"error: {exc}"

    rows: list[tuple[str, str, str, str, str, str, str, int]] = []
    cve_map: list[tuple[str, str]] = []
    try:
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            edb_id = (row.get("id") or "").strip()
            if not edb_id:
                continue
            verified = 1 if (row.get("verified") or "").strip() in {
                "1",
                "true",
                "True",
            } else 0
            rows.append(
                (
                    edb_id,
                    row.get("file") or "",
                    row.get("description") or "",
                    row.get("date_published") or "",
                    row.get("author") or "",
                    row.get("platform") or "",
                    row.get("type") or "",
                    verified,
                )
            )
            codes = (row.get("codes") or "").strip()
            if not codes:
                continue
            for entry in codes.split(";"):
                entry = entry.strip().upper()
                if entry.startswith("CVE-"):
                    cve_map.append((edb_id, entry))
    except (ValueError, KeyError) as exc:
        return f"error: {exc}"

    iso = _iso_now()
    try:
        with intel._lock:
            intel._ensure_open()
            assert intel._conn is not None
            with intel._conn:
                intel._conn.execute("DELETE FROM exploits")
                intel._conn.execute("DELETE FROM exploit_cve_map")
                intel._conn.executemany(
                    "INSERT OR IGNORE INTO exploits(edb_id, file_path, description,"
                    " date_published, author, platform, type, verified)"
                    " VALUES(?,?,?,?,?,?,?,?)",
                    rows,
                )
                intel._conn.executemany(
                    "INSERT OR IGNORE INTO exploit_cve_map(edb_id, cve_id)"
                    " VALUES(?,?)",
                    cve_map,
                )
                intel._record_sync("exploitdb", iso, len(rows))
    except sqlite3.Error as exc:
        return f"error: {exc}"

    return f"ok: {len(rows)} rows"


# ---------------------------------------------------------------------------
# MITRE ATT&CK (Enterprise)
# ---------------------------------------------------------------------------


def _attack_external_id(obj: dict[str, Any], source_name: str | None = None) -> str:
    refs = obj.get("external_references") or []
    if source_name is None:
        if refs and isinstance(refs[0], dict):
            return refs[0].get("external_id") or ""
        return ""
    for ref in refs:
        if isinstance(ref, dict) and ref.get("source_name") == source_name:
            return ref.get("external_id") or ""
    return ""


def _attack_external_url(obj: dict[str, Any], source_name: str | None = None) -> str:
    refs = obj.get("external_references") or []
    if source_name is None:
        if refs and isinstance(refs[0], dict):
            return refs[0].get("url") or ""
        return ""
    for ref in refs:
        if isinstance(ref, dict) and ref.get("source_name") == source_name:
            return ref.get("url") or ""
    return ""


def sync_attack(intel) -> str:
    try:
        raw = intel._download(_ATTACK_JSON_URL)
        data = json.loads(raw.decode("utf-8"))
    except (
        OSError,
        urllib.error.URLError,
        urllib.error.HTTPError,
        json.JSONDecodeError,
    ) as exc:
        return f"error: {exc}"

    objects = data.get("objects") or []
    if not isinstance(objects, list):
        return "error: unexpected ATT&CK bundle shape"

    tactic_rows: list[tuple[str, str, str, str]] = []
    shortname_to_tactic: dict[str, str] = {}

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "x-mitre-tactic" or obj.get("revoked"):
            continue
        tactic_id = _attack_external_id(obj)
        if not tactic_id:
            continue
        shortname = obj.get("x_mitre_shortname") or ""
        if shortname:
            shortname_to_tactic[shortname] = tactic_id
        tactic_rows.append(
            (
                tactic_id,
                obj.get("name") or "",
                obj.get("description") or "",
                _attack_external_url(obj),
            )
        )

    technique_rows: list[tuple[str, str, str, str, str, int, str]] = []
    technique_tactic_map: list[tuple[str, str]] = []

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        technique_id = _attack_external_id(obj, source_name="mitre-attack")
        if not technique_id:
            continue
        is_sub = bool(obj.get("x_mitre_is_subtechnique"))
        parent_id = technique_id.split(".")[0] if is_sub else ""
        url = f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"

        primary_tactic = ""
        for phase in obj.get("kill_chain_phases") or []:
            if not isinstance(phase, dict):
                continue
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            shortname = phase.get("phase_name") or ""
            tactic_id = shortname_to_tactic.get(shortname, "")
            if not tactic_id:
                continue
            if not primary_tactic:
                primary_tactic = tactic_id
            technique_tactic_map.append((technique_id, tactic_id))

        technique_rows.append(
            (
                technique_id,
                obj.get("name") or "",
                obj.get("description") or "",
                primary_tactic,
                url,
                1 if is_sub else 0,
                parent_id,
            )
        )

    iso = _iso_now()
    try:
        with intel._lock:
            intel._ensure_open()
            assert intel._conn is not None
            with intel._conn:
                intel._conn.execute("DELETE FROM attack_tactics")
                intel._conn.execute("DELETE FROM attack_techniques")
                intel._conn.execute("DELETE FROM attack_technique_tactic_map")
                intel._conn.executemany(
                    "INSERT INTO attack_tactics(tactic_id, name, description, url)"
                    " VALUES(?,?,?,?)",
                    tactic_rows,
                )
                intel._conn.executemany(
                    "INSERT INTO attack_techniques(technique_id, name, description,"
                    " tactic, url, is_subtechnique, parent_id)"
                    " VALUES(?,?,?,?,?,?,?)",
                    technique_rows,
                )
                intel._conn.executemany(
                    "INSERT OR IGNORE INTO attack_technique_tactic_map"
                    "(technique_id, tactic_id) VALUES(?,?)",
                    technique_tactic_map,
                )
                intel._record_sync("attack", iso, len(technique_rows))
    except sqlite3.Error as exc:
        return f"error: {exc}"

    return f"ok: {len(technique_rows)} rows"


# ---------------------------------------------------------------------------
# CAPEC
# ---------------------------------------------------------------------------


def _capec_child_text(elem: ET.Element, local: str) -> str:
    child = elem.find(f"c:{local}", _CAPEC_NS)
    if child is None:
        return ""
    return "".join(child.itertext()).strip()


def sync_capec(intel) -> str:
    try:
        raw = intel._download(_CAPEC_XML_URL)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        return f"error: {exc}"

    try:
        tree = ET.parse(io.BytesIO(raw))
    except ET.ParseError as exc:
        return f"error: {exc}"

    root = tree.getroot()
    capec_rows: list[tuple[str, str, str, str, str, str]] = []
    cwe_map: list[tuple[str, str]] = []

    for elem in root.iter(f"{{{_CAPEC_NS['c']}}}Attack_Pattern"):
        capec_num = elem.get("ID") or ""
        if not capec_num:
            continue
        capec_id = f"CAPEC-{capec_num}"
        name = elem.get("Name", "") or ""

        desc_el = elem.find("c:Description", _CAPEC_NS)
        description = (
            "".join(desc_el.itertext()).strip() if desc_el is not None else ""
        )
        likelihood = _capec_child_text(elem, "Likelihood_Of_Attack")
        severity = _capec_child_text(elem, "Typical_Severity")
        url = f"https://capec.mitre.org/data/definitions/{capec_num}.html"

        capec_rows.append(
            (capec_id, name, description, likelihood, severity, url)
        )

        related = elem.find("c:Related_Weaknesses", _CAPEC_NS)
        if related is not None:
            for rw in related.findall("c:Related_Weakness", _CAPEC_NS):
                cwe_num = rw.get("CWE_ID") or ""
                if cwe_num:
                    cwe_map.append((capec_id, f"CWE-{cwe_num}"))

    iso = _iso_now()
    try:
        with intel._lock:
            intel._ensure_open()
            assert intel._conn is not None
            with intel._conn:
                intel._conn.execute("DELETE FROM capec")
                intel._conn.execute("DELETE FROM capec_cwe_map")
                intel._conn.executemany(
                    "INSERT INTO capec(capec_id, name, description,"
                    " likelihood_of_attack, typical_severity, url)"
                    " VALUES(?,?,?,?,?,?)",
                    capec_rows,
                )
                intel._conn.executemany(
                    "INSERT OR IGNORE INTO capec_cwe_map(capec_id, cwe_id)"
                    " VALUES(?,?)",
                    cwe_map,
                )
                intel._record_sync("capec", iso, len(capec_rows))
    except sqlite3.Error as exc:
        return f"error: {exc}"

    return f"ok: {len(capec_rows)} rows"


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------


def lookup_exploits_for_cve(intel, cve_id: str) -> list[ExploitInfo]:
    cve_id = (cve_id or "").strip().upper()
    if not cve_id:
        return []
    out: list[ExploitInfo] = []
    with intel._lock:
        intel._ensure_open()
        assert intel._conn is not None
        rows = intel._conn.execute(
            "SELECT e.edb_id, e.file_path, e.description, e.date_published,"
            " e.author, e.platform, e.type, e.verified"
            " FROM exploit_cve_map m"
            " JOIN exploits e ON e.edb_id = m.edb_id"
            " WHERE m.cve_id = ?",
            (cve_id,),
        ).fetchall()
        for row in rows:
            edb_id = row["edb_id"]
            cve_rows = intel._conn.execute(
                "SELECT cve_id FROM exploit_cve_map WHERE edb_id = ?",
                (edb_id,),
            ).fetchall()
            cves = tuple(r["cve_id"] for r in cve_rows)
            out.append(
                ExploitInfo(
                    edb_id=edb_id,
                    file_path=row["file_path"] or "",
                    description=row["description"] or "",
                    date_published=row["date_published"] or "",
                    author=row["author"] or "",
                    platform=row["platform"] or "",
                    type=row["type"] or "",
                    verified=bool(row["verified"]),
                    cve_ids=cves,
                )
            )
    return out


def lookup_attack_technique(intel, technique_id: str) -> AttackTechnique | None:
    technique_id = (technique_id or "").strip().upper()
    if not technique_id:
        return None
    with intel._lock:
        intel._ensure_open()
        assert intel._conn is not None
        row = intel._conn.execute(
            "SELECT technique_id, name, description, tactic, url,"
            " is_subtechnique, parent_id"
            " FROM attack_techniques WHERE technique_id = ?",
            (technique_id,),
        ).fetchone()
    if row is None:
        return None
    return AttackTechnique(
        technique_id=row["technique_id"],
        name=row["name"] or "",
        description=row["description"] or "",
        tactic=row["tactic"] or "",
        url=row["url"] or "",
        is_subtechnique=bool(row["is_subtechnique"]),
        parent_id=row["parent_id"] or "",
    )


def lookup_capec(intel, capec_id: str) -> CapecInfo | None:
    capec_id = (capec_id or "").strip().upper()
    if not capec_id:
        return None
    with intel._lock:
        intel._ensure_open()
        assert intel._conn is not None
        row = intel._conn.execute(
            "SELECT capec_id, name, description, likelihood_of_attack,"
            " typical_severity, url FROM capec WHERE capec_id = ?",
            (capec_id,),
        ).fetchone()
        if row is None:
            return None
        cwe_rows = intel._conn.execute(
            "SELECT cwe_id FROM capec_cwe_map WHERE capec_id = ?",
            (capec_id,),
        ).fetchall()
    return CapecInfo(
        capec_id=row["capec_id"],
        name=row["name"] or "",
        description=row["description"] or "",
        likelihood_of_attack=row["likelihood_of_attack"] or "",
        typical_severity=row["typical_severity"] or "",
        url=row["url"] or "",
        cwe_ids=tuple(r["cwe_id"] for r in cwe_rows),
    )


def attack_for_cwe(intel, cwe_id: str) -> list[CapecInfo]:
    cwe_id = (cwe_id or "").strip().upper()
    if not cwe_id:
        return []
    out: list[CapecInfo] = []
    with intel._lock:
        intel._ensure_open()
        assert intel._conn is not None
        rows = intel._conn.execute(
            "SELECT c.capec_id, c.name, c.description, c.likelihood_of_attack,"
            " c.typical_severity, c.url"
            " FROM capec_cwe_map m"
            " JOIN capec c ON c.capec_id = m.capec_id"
            " WHERE m.cwe_id = ?",
            (cwe_id,),
        ).fetchall()
        for row in rows:
            capec_id = row["capec_id"]
            cwe_rows = intel._conn.execute(
                "SELECT cwe_id FROM capec_cwe_map WHERE capec_id = ?",
                (capec_id,),
            ).fetchall()
            out.append(
                CapecInfo(
                    capec_id=capec_id,
                    name=row["name"] or "",
                    description=row["description"] or "",
                    likelihood_of_attack=row["likelihood_of_attack"] or "",
                    typical_severity=row["typical_severity"] or "",
                    url=row["url"] or "",
                    cwe_ids=tuple(r["cwe_id"] for r in cwe_rows),
                )
            )
    return out


def extended_counts(intel) -> dict[str, int]:
    with intel._lock:
        intel._ensure_open()
        assert intel._conn is not None
        return {
            "exploits": intel._conn.execute(
                "SELECT COUNT(*) FROM exploits"
            ).fetchone()[0],
            "attack_techniques": intel._conn.execute(
                "SELECT COUNT(*) FROM attack_techniques"
            ).fetchone()[0],
            "attack_tactics": intel._conn.execute(
                "SELECT COUNT(*) FROM attack_tactics"
            ).fetchone()[0],
            "capec": intel._conn.execute(
                "SELECT COUNT(*) FROM capec"
            ).fetchone()[0],
        }


__all__ = [
    "AttackTactic",
    "AttackTechnique",
    "CapecInfo",
    "ExploitInfo",
    "attack_for_cwe",
    "extended_counts",
    "lookup_attack_technique",
    "lookup_capec",
    "lookup_exploits_for_cve",
    "register_extended_schema",
    "sync_attack",
    "sync_capec",
    "sync_exploitdb",
    "sync_nvd",
]
