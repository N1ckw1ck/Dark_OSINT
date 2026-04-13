#!/usr/bin/env python3

'''
d_khaeos.py — Khaeos Dark Web Intelligence Index

Local FastAPI-backed search index and time-series tracker for .onion sites.
Consumes JSON output from d_mnemosyne.py (single-scan or batch) and builds
a queryable SQLite database with historical scan records per site.

Erebus → Hemera → Mnemosyne
Now there is Khaeos

Features:
  • Ingests single-scan and batch Mnemosyne JSON files
  • Stores full scan history per URL — reachability, latency, risk, headers, canary
  • Time-series tracking: uptime %, latency trends, risk score drift
  • Cybersecurity focused engine: faceted filters by risk, canary, blacklist, clearnet leak
  • Auto-infers site category from title/snippet keywords
  • Manual tagging via API
  • REST API served to khaeos_ui.html

Usage:
  python d_khaeos.py                        Start the web UI server (localhost:7777)
                                            Will create khaeos.db (MySQL)
  python d_khaeos.py --ingest <file.json>   Ingest a Mnemosyne JSON file, then exit
  python d_khaeos.py --ingest <file.json> --serve   Ingest then start server
  python d_khaeos.py --db <path>            Use a custom database path (allows external drive)

Dependencies:
  pip install fastapi uvicorn python-multipart

For authorized research and investigative use only.
'''

from __future__ import annotations

import json
import sqlite3
import sys
import webbrowser
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator
from urllib.parse import urlparse

try:
    from fastapi import FastAPI, HTTPException, UploadFile, File, Query # type: ignore
    from fastapi.middleware.cors import CORSMiddleware # type: ignore
    from fastapi.responses import HTMLResponse, JSONResponse # type: ignore
    from fastapi.staticfiles import StaticFiles # type: ignore
    import uvicorn # type: ignore
    _fastapi_available = True
except ImportError:
    _fastapi_available = False

# ANSI
R = '\033[91m'
G = '\033[92m'
Y = '\033[93m'
B = '\033[94m'
C = '\033[96m'
W = '\033[97m'
DIM = '\033[2m'
BOLD = '\033[1m'
RESET = '\033[0m'

BANNER = f'''{C}
   ▄█   ▄█▄    ▄█    █▄       ▄████████    ▄████████  ▄██████▄     ▄████████ 
  ███ ▄███▀   ███    ███     ███    ███   ███    ███ ███    ███   ███    ███ 
  ███▐██▀     ███    ███     ███    ███   ███    █▀  ███    ███   ███    █▀  
 ▄█████▀     ▄███▄▄▄▄███▄▄   ███    ███  ▄███▄▄▄     ███    ███   ███        
▀▀█████▄    ▀▀███▀▀▀▀███▀  ▀███████████ ▀▀███▀▀▀     ███    ███ ▀███████████ 
  ███▐██▄     ███    ███     ███    ███   ███    █▄  ███    ███          ███ 
  ███ ▀███▄   ███    ███     ███    ███   ███    ███ ███    ███    ▄█    ███ 
  ███   ▀█▀   ███    █▀      ███    █▀    ██████████  ▀██████▀   ▄████████▀  
  ▀                                                                          
{RESET}

{DIM}Χαεος · ฿łɨᴨđ Ҡħⱥєѳꮥ ɨꮥ ƀʉгꮥŧ ѳƿєᴨ{RESET}

{DIM}D̳͉ͯ͗ark̢͘ ̯̩Ẃ͠e͇͈͢͝b̦͔ Ī̉nt͒ͪelli͍͕ͦ̅g͖̻ence ̧̬̻̀Ind̪̺e͇̭x{RESET}

M̮nemo̥ͧsy̸͎ne → {C}K̊ͬh̓̂aeo̱͇s{RESET}

'''

DIVIDER = '─' * 62

# Config
DEFAULT_DB = Path(__file__).parent / 'khaeos.db'
DEFAULT_PORT = 7777
DEFAULT_HOST = '127.0.0.1'
UI_FILE = Path(__file__).parent / 'khaeos_ui.html'

# Category inference keywords
# Each category maps to a list of keywords checked against the site's page_title and snippet from Erebus data.
CATEGORY_KEYWORDS: dict[str, list[str]] = {
    'forum': ['forum', 'board', 'thread', 'discussion', 'post', 'community', 'chan'],
    'market': ['market', 'shop', 'store', 'vendor', 'listing', 'buy', 'sell', 'drugs', 'escrow'],
    'chat': ['chat', 'messenger', 'message', 'inbox', 'jabber', 'xmpp', 'irc', 'room'],
    'email': ['email', 'mail', 'inbox', 'smtp', 'webmail'],
    'news': ['news', 'press', 'article', 'journal', 'media', 'blog', 'report'],
    'wiki': ['wiki', 'encyclopedia', 'knowledge', 'library', 'archive', 'docs'],
    'leaks': ['leak', 'dump', 'breach', 'whistleblow', 'expose', 'database', 'paste'],
    'crypto': ['bitcoin', 'crypto', 'wallet', 'monero', 'ethereum', 'btc', 'xmr', 'exchange', 'mixer'],
    'hacking': ['hack', 'exploit', 'vuln', 'malware', 'rat', 'tool', 'payload', 'zero-day', 'crack'],
    'hosting': ['hosting', 'host', 'server', 'vps', 'onion hosting', 'bulletproof'],
    'social': ['social', 'profile', 'network', 'follow', 'friend', 'reddit', 'mastodon'],
    'search': ['search', 'index', 'directory', 'crawler', 'aggregator', 'engine'],
    'privacy': ['privacy', 'vpn', 'proxy', 'anon', 'security', 'opsec', 'pgp', 'canary'],
    'services': ['service', 'api', 'tool', 'util', 'convert', 'generate', 'verify'],
    'uncategorized': [],
}

# Database
SCHEMA = '''
CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL UNIQUE,
    first_seen TEXT NOT NULL,
    last_seen TEXT,
    last_scan_time TEXT,
    page_title TEXT DEFAULT '',
    category TEXT DEFAULT 'uncategorized',
    tags TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    total_scans INTEGER DEFAULT 0,
    scans_reachable INTEGER DEFAULT 0,
    uptime_pct REAL DEFAULT 0.0,
    avg_latency_ms REAL,
    last_risk_level TEXT DEFAULT 'UNKNOWN',
    last_risk_score INTEGER DEFAULT 0,
    blacklisted INTEGER DEFAULT 0,
    clearnet_leak INTEGER DEFAULT 0,
    clearnet_redirect INTEGER DEFAULT 0,
    has_canary INTEGER DEFAULT 0,
    canary_valid INTEGER DEFAULT 0,
    security_headers_count INTEGER DEFAULT 0,
    web_server TEXT DEFAULT '',
    raw_html_length INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id),
    host TEXT NOT NULL,
    scan_time TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    reachable INTEGER NOT NULL,
    status_code INTEGER,
    latency_ms REAL,
    risk_level TEXT,
    risk_score INTEGER,
    risk_flags TEXT DEFAULT '',
    blacklisted INTEGER DEFAULT 0,
    clearnet_redirect INTEGER DEFAULT 0,
    clearnet_leaks INTEGER DEFAULT 0,
    security_headers_present TEXT DEFAULT '',
    security_headers_missing TEXT DEFAULT '',
    has_canary INTEGER DEFAULT 0,
    canary_valid INTEGER DEFAULT 0,
    canary_fingerprint TEXT DEFAULT '',
    web_server TEXT DEFAULT '',
    page_title TEXT DEFAULT '',
    raw_html_length INTEGER DEFAULT 0,
    script_count INTEGER DEFAULT 0,
    inline_scripts INTEGER DEFAULT 0,
    fingerprint_vectors TEXT DEFAULT '',
    forms_count INTEGER DEFAULT 0,
    tech_stack TEXT DEFAULT '',
    batch_id TEXT,
    full_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS batches (
    batch_id TEXT PRIMARY KEY,
    ingested_at TEXT NOT NULL,
    source_file TEXT DEFAULT '',
    total_reports INTEGER DEFAULT 0,
    reachable_count INTEGER DEFAULT 0,
    blacklisted_count INTEGER DEFAULT 0,
    avg_risk_score REAL DEFAULT 0.0,
    avg_latency_ms REAL,
    avg_sec_headers REAL DEFAULT 0.0
);

CREATE INDEX IF NOT EXISTS idx_scans_site_id ON scans(site_id);
CREATE INDEX IF NOT EXISTS idx_scans_scan_time ON scans(scan_time);
CREATE INDEX IF NOT EXISTS idx_sites_host ON sites(host);
CREATE INDEX IF NOT EXISTS idx_sites_category ON sites(category);
CREATE INDEX IF NOT EXISTS idx_sites_risk ON sites(last_risk_level);
'''


@contextmanager
def get_db(db_path: Path) -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Path) -> None:
    with get_db(db_path) as conn:
        conn.executescript(SCHEMA)


# Category inference
def infer_category(title: str, snippet: str = '') -> str:
    text = (title + ' ' + snippet).lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        if category == 'uncategorized':
            continue
        for kw in keywords:
            if kw in text:
                return category
    return 'uncategorized'


# JSON normalization
# Handles both single-scan (dict with top-level scan fields) and batch (dict with top-level 'reports' list)
def normalize_mnemosyne_json(raw: dict[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
    '''
    Return a flat list of individual report dicts regardless of JSON format.
    Single-scan: raw itself is the report (has 'target' and 'scan_time' at top level).
    Batch: raw has a 'reports' key containing the list.
    '''
    if 'reports' in raw and isinstance(raw['reports'], list):
        batch_id = str(raw.get('batch_scan_time', ''))
        return [r for r in raw['reports'] if isinstance(r, dict)], batch_id or None  # type: ignore[union-attr]
    if 'target' in raw and 'scan_time' in raw:
        return [raw], None
    raise ValueError(
        'Unrecognized Mnemosyne JSON format. '
        'Expected either a single-scan report (with "target" + "scan_time") '
        'or a batch report (with "reports" list).'
    )


def extract_host(target: str) -> str:
    parsed = urlparse(target)
    return parsed.netloc or parsed.path.lstrip('/')


# Ingest
def ingest_report(conn: sqlite3.Connection, report: dict[str, Any], batch_id: str | None = None) -> tuple[bool, str]:
    '''
    Ingest a single report dict into the database.
    Returns (success, message).
    '''
    target: str = str(report.get('target', ''))
    if not target:
        return False, 'Report missing target field'

    host = extract_host(target)
    if not host:
        return False, f'Could not extract host from target: {target}'

    scan_time: str = str(report.get('scan_time', datetime.now(timezone.utc).isoformat()))
    ingested_at: str = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

 # Check for duplicate scan (same host + scan_time)
    existing = conn.execute(
        'SELECT id FROM scans WHERE host = ? AND scan_time = ?',
        (host, scan_time)
    ).fetchone()
    if existing:
        return False, f'Duplicate scan for {host} at {scan_time} — skipped'

 # Extract fields from report
    reach: dict[str, Any] = report.get('reachability') or {}
    reputation: dict[str, Any] | None = report.get('reputation')
    headers_data: dict[str, Any] | None = report.get('headers')
    canary_data: dict[str, Any] | None = report.get('canary')
    scripts_data: dict[str, Any] | None = report.get('scripts')
    resources_data: dict[str, Any] | None = report.get('resources')
    forms_data: dict[str, Any] | None = report.get('forms')
    tech_data: dict[str, Any] | None = report.get('tech')
    risk_data: dict[str, Any] | None = report.get('risk')

    reachable = int(bool(reach.get('reachable', False)))
    status_code = reach.get('status_code')
    latency_ms = reach.get('latency_ms')
    clr_redirect = int(bool(reach.get('clearnet_redirect', False)))

    risk_level = str(risk_data.get('level', 'UNKNOWN')) if risk_data else 'UNKNOWN'
    risk_score = int(risk_data.get('score', 0)) if risk_data else 0
    risk_flags = json.dumps(risk_data.get('flags', [])) if risk_data else '[]'

    blacklisted = int(bool(reputation and reputation.get('blacklisted', False)))

    sec_present: list[str] = []
    sec_missing: list[str] = []
    web_server = ''
    if headers_data:
        sec_present = list(headers_data.get('security_headers_present') or [])
        sec_missing = list(headers_data.get('security_headers_missing') or [])
        web_server = str(headers_data.get('server') or '')

    has_canary = 0
    canary_valid = 0
    canary_fp = ''
    if canary_data:
        has_canary = int(bool(canary_data.get('canary_found', False)))
        canary_valid = int(bool(canary_data.get('signature_valid', False)))
        canary_fp = str(canary_data.get('signing_fingerprint') or '')

    clearnet_leaks = 0
    if resources_data:
        leaks = resources_data.get('clearnet_leaks') or [] # type: ignore
        clearnet_leaks = len(leaks) if isinstance(leaks, list) else int(leaks) # type: ignore

    script_count = 0
    inline_scripts = 0
    fp_vectors: list[str] = []
    if scripts_data:
        script_count = int(scripts_data.get('total_script_tags', 0))
        inline_scripts = int(scripts_data.get('inline_scripts', 0))
        fp_vectors = list(scripts_data.get('fingerprint_vectors') or [])

    forms_count = 0
    if forms_data:
        forms_count = int(forms_data.get('total_forms', 0))

    tech_stack: dict[str, Any] = {}
    if tech_data:
        tech_stack = {
            'web_server': tech_data.get('web_server', ''),
            'cms_hints': tech_data.get('cms_hints', []),
            'framework_hints': tech_data.get('framework_hints', []),
            'language_hints': tech_data.get('language_hints', []),
        }

    page_title = str(report.get('page_title') or '')
    raw_html_length = int(report.get('raw_html_length') or 0)

 # Upsert site row 
    site_row = conn.execute('SELECT * FROM sites WHERE host = ?', (host,)).fetchone()

    if site_row is None:
        category = infer_category(page_title)
        conn.execute('''
            INSERT INTO sites (
                host, first_seen, last_seen, last_scan_time, page_title, category,
                total_scans, scans_reachable, uptime_pct,
                avg_latency_ms, last_risk_level, last_risk_score,
                blacklisted, clearnet_leak, clearnet_redirect,
                has_canary, canary_valid, security_headers_count,
                web_server, raw_html_length
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            host, scan_time, scan_time, scan_time, page_title, category,
            1,
            reachable,
            100.0 if reachable else 0.0,
            float(latency_ms) if latency_ms is not None else None,
            risk_level, risk_score,
            blacklisted, min(1, clearnet_leaks), clr_redirect,
            has_canary, canary_valid, len(sec_present),
            web_server, raw_html_length,
        ))
        site_id = conn.execute('SELECT id FROM sites WHERE host = ?', (host,)).fetchone()['id']
    else:
        site_id = site_row['id']
        total_scans = int(site_row['total_scans']) + 1
        scans_reachable = int(site_row['scans_reachable']) + reachable
        uptime_pct = round((scans_reachable / total_scans) * 100, 1)

     # Rolling average latency
        old_avg = site_row['avg_latency_ms']
        old_total = int(site_row['total_scans'])
        if latency_ms is not None:
            if old_avg is not None:
                new_avg: float | None = ((old_avg * old_total) + float(latency_ms)) / total_scans
            else:
                new_avg = float(latency_ms)
        else:
            new_avg = old_avg

     # Refresh title if we just got one and didn't have one before
        new_title = page_title if page_title else str(site_row['page_title'] or '')
        new_category = str(site_row['category'])
        if new_category == 'uncategorized' and new_title:
            new_category = infer_category(new_title)

        conn.execute('''
            UPDATE sites SET
                last_seen = ?,
                last_scan_time = ?,
                page_title = ?,
                category = ?,
                total_scans = ?,
                scans_reachable = ?,
                uptime_pct = ?,
                avg_latency_ms = ?,
                last_risk_level = ?,
                last_risk_score = ?,
                blacklisted = MAX(blacklisted, ?),
                clearnet_leak = MAX(clearnet_leak, ?),
                clearnet_redirect = MAX(clearnet_redirect, ?),
                has_canary = MAX(has_canary, ?),
                canary_valid = ?,
                security_headers_count = ?,
                web_server = ?,
                raw_html_length = ?
            WHERE id = ?
        ''', (
            scan_time, scan_time, new_title, new_category,
            total_scans, scans_reachable, uptime_pct, new_avg,
            risk_level, risk_score,
            blacklisted, min(1, clearnet_leaks), clr_redirect,
            has_canary, canary_valid, len(sec_present),
            web_server if web_server else str(site_row['web_server'] or ''),
            raw_html_length,
            site_id,
        ))

 # Insert scan row
    conn.execute('''
        INSERT INTO scans (
            site_id, host, scan_time, ingested_at,
            reachable, status_code, latency_ms,
            risk_level, risk_score, risk_flags,
            blacklisted, clearnet_redirect, clearnet_leaks,
            security_headers_present, security_headers_missing,
            has_canary, canary_valid, canary_fingerprint,
            web_server, page_title, raw_html_length,
            script_count, inline_scripts, fingerprint_vectors,
            forms_count, tech_stack, batch_id, full_json
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (
        site_id, host, scan_time, ingested_at,
        reachable, status_code,
        float(latency_ms) if latency_ms is not None else None,
        risk_level, risk_score, risk_flags,
        blacklisted, clr_redirect, clearnet_leaks,
        json.dumps(sec_present), json.dumps(sec_missing),
        has_canary, canary_valid, canary_fp,
        web_server, page_title, raw_html_length,
        script_count, inline_scripts, json.dumps(fp_vectors),
        forms_count, json.dumps(tech_stack),
        batch_id,
        json.dumps(report),
    ))

    return True, f'Ingested: {host}  [{risk_level}]'


def ingest_file(json_path: Path, db_path: Path) -> tuple[int, int, list[str]]:
    '''
    Parse and ingest a Mnemosyne JSON file.
    Returns (ingested_count, skipped_count, error_messages).
    '''
    if not json_path.exists():
        return 0, 0, [f'File not found: {json_path}']

    try:
        with open(json_path, 'r', encoding='utf-8') as fh:
            raw: dict[str, Any] = json.load(fh)
    except json.JSONDecodeError as e:
        return 0, 0, [f'JSON parse error: {e}']

    try:
        reports, batch_id = normalize_mnemosyne_json(raw)
    except ValueError as e:
        return 0, 0, [str(e)]

    ingested = 0
    skipped  = 0
    ingested_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    errors: list[str] = []

    init_db(db_path)
    with get_db(db_path) as conn:
        for report in reports:
            ok, msg = ingest_report(conn, report, batch_id)
            if ok:
                ingested += 1
                print(f'  {G}✓{RESET} {msg}')
            else:
                skipped += 1
                print(f'  {DIM}↷ {msg}{RESET}')

    if batch_id:
        with get_db(db_path) as conn:
            # compute aggregates from what was just inserted
            agg = conn.execute('''
                SELECT COUNT(*) as n,
                       SUM(reachable) as reach,
                       SUM(blacklisted) as bl,
                       AVG(risk_score) as avg_risk,
                       AVG(latency_ms) as avg_lat,
                       AVG(json_array_length(security_headers_present)) as avg_hdrs
                FROM scans WHERE batch_id = ?
            ''', (batch_id,)).fetchone()
            conn.execute('''
                INSERT OR REPLACE INTO batches
                (batch_id, ingested_at, source_file, total_reports, reachable_count,
                 blacklisted_count, avg_risk_score, avg_latency_ms, avg_sec_headers)
                VALUES (?,?,?,?,?,?,?,?,?)
            ''', (
                batch_id, ingested_at, str(json_path),
                agg['n'], agg['reach'] or 0, agg['bl'] or 0,
                agg['avg_risk'] or 0.0, agg['avg_lat'], agg['avg_hdrs'] or 0.0,
            ))

    return ingested, skipped, errors


# FastAPI app
def create_app(db_path: Path) -> 'FastAPI':
    app = FastAPI(title='Khaeos', version='1.0.0', docs_url=None, redoc_url=None) # type: ignore
    app.add_middleware(
        CORSMiddleware, # type: ignore
        allow_origins=['*'],
        allow_methods=['*'],
        allow_headers=['*'],
    )

 # Serve UI
    @app.get('/', response_class=HTMLResponse) # type: ignore
    async def serve_ui() -> HTMLResponse: # type: ignore
        if UI_FILE.exists():
            return HTMLResponse(content=UI_FILE.read_text(encoding='utf-8')) # type: ignore
        return HTMLResponse(content='<h1>khaeos_ui.html not found</h1>', status_code=404) # type: ignore

 # Stats overview
    @app.get('/api/stats')
    async def get_stats() -> JSONResponse: # type: ignore
        with get_db(db_path) as conn:
            total_sites = conn.execute('SELECT COUNT(*) FROM sites').fetchone()[0]
            total_scans = conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
            reachable = conn.execute(
                "SELECT COUNT(*) FROM sites WHERE last_risk_level != 'UNKNOWN' AND uptime_pct > 0"
            ).fetchone()[0]
            blacklisted = conn.execute('SELECT COUNT(*) FROM sites WHERE blacklisted = 1').fetchone()[0]
            high_risk = conn.execute(
                "SELECT COUNT(*) FROM sites WHERE last_risk_level IN ('HIGH','CRITICAL')"
            ).fetchone()[0]
            canary_ok = conn.execute('SELECT COUNT(*) FROM sites WHERE canary_valid = 1').fetchone()[0]
            cats = conn.execute(
                'SELECT category, COUNT(*) as n FROM sites GROUP BY category ORDER BY n DESC'
            ).fetchall()
            risk_dist = conn.execute(
                'SELECT last_risk_level, COUNT(*) as n FROM sites GROUP BY last_risk_level'
            ).fetchall()
        return JSONResponse({ # type: ignore
            'total_sites': total_sites,
            'total_scans': total_scans,
            'reachable': reachable,
            'blacklisted': blacklisted,
            'high_risk': high_risk,
            'canary_valid': canary_ok,
            'categories': [dict(r) for r in cats],
            'risk_dist': [dict(r) for r in risk_dist],
        })

 # Search / list sites
    @app.get('/api/sites')
    async def search_sites( # type: ignore
        q: str = Query(''), # type: ignore
        category: str = Query(''), # type: ignore
        risk_level: str = Query(''), # type: ignore
        reachable: str = Query(''), # type: ignore '1', '0', ''
        blacklisted: str = Query(''), # type: ignore
        has_canary: str = Query(''), # type: ignore
        canary_valid: str = Query(''), # type: ignore
        no_clearnet: str = Query(''), # type: ignore '1' = exclude clearnet leaks/redirects
        sort: str = Query('last_seen'), # type: ignore
        order: str = Query('desc'), # type: ignore
        limit: int = Query(50), # type: ignore
        offset: int = Query(0), # type: ignore
    ) -> JSONResponse:
        where: list[str] = []
        params: list[Any] = []

        if q:
            where.append('(host LIKE ? OR page_title LIKE ? OR tags LIKE ?)')
            like = f'%{q}%'
            params += [like, like, like]
        if category:
            where.append('category = ?')
            params.append(category)
        if risk_level:
            levels = [l.strip().upper() for l in risk_level.split(',')]
            where.append(f'last_risk_level IN ({",".join("?" * len(levels))})')
            params.extend(levels)
        if reachable == '1':
            where.append('scans_reachable > 0')
        elif reachable == '0':
            where.append('scans_reachable = 0')
        if blacklisted == '1':
            where.append('blacklisted = 1')
        elif blacklisted == '0':
            where.append('blacklisted = 0')
        if has_canary == '1':
            where.append('has_canary = 1')
        if canary_valid == '1':
            where.append('canary_valid = 1')
        if no_clearnet == '1':
            where.append('clearnet_leak = 0 AND clearnet_redirect = 0')

        safe_sort = sort if sort in ('last_seen','first_seen','uptime_pct','last_risk_score','avg_latency_ms','page_title','host') else 'last_seen'
        safe_order = 'ASC' if order.upper() == 'ASC' else 'DESC'

        clause = ('WHERE ' + ' AND '.join(where)) if where else ''
        sql = f'''
            SELECT * FROM sites {clause}
            ORDER BY {safe_sort} {safe_order}
            LIMIT ? OFFSET ?
        '''
        params += [limit, offset]

        count_sql = f'SELECT COUNT(*) FROM sites {clause}'

        with get_db(db_path) as conn:
            rows = conn.execute(sql, params).fetchall()
            total = conn.execute(count_sql, params[:-2]).fetchone()[0]

        return JSONResponse({ # type: ignore
            'total': total,
            'offset': offset,
            'limit': limit,
            'sites': [dict(r) for r in rows],
        })

 # Single site detail
    @app.get('/api/sites/{host:path}')
    async def get_site(host: str) -> JSONResponse: # type: ignore
        host = host.strip('/')
        with get_db(db_path) as conn:
            site = conn.execute('SELECT * FROM sites WHERE host = ?', (host,)).fetchone()
            if not site:
                raise HTTPException(status_code=404, detail='Site not found') # type: ignore
            scans = conn.execute(
                'SELECT * FROM scans WHERE host = ? ORDER BY scan_time ASC',
                (host,)
            ).fetchall()
        return JSONResponse({ # type: ignore
            'site': dict(site),
            'scans': [dict(s) for s in scans],
        })

 # Time-series data for charts
    @app.get('/api/timeseries/{host:path}')
    async def get_timeseries(host: str) -> JSONResponse: # type: ignore
        host = host.strip('/')
        with get_db(db_path) as conn:
            rows = conn.execute('''
                SELECT scan_time, reachable, latency_ms, risk_score, risk_level,
                       blacklisted, has_canary, canary_valid,
                       security_headers_present, clearnet_leaks, script_count
                FROM scans WHERE host = ?
                ORDER BY scan_time ASC
            ''', (host,)).fetchall()

        if not rows:
            raise HTTPException(status_code=404, detail='No scan history for this host') # type: ignore

        series: dict[str, list[Any]] = {
            'labels': [],
            'reachable': [],
            'latency_ms': [],
            'risk_score': [],
            'risk_level': [],
            'clearnet_leaks': [],
            'script_count': [],
            'sec_header_count': [],
            'canary_valid': [],
        }
        for row in rows:
            series['labels'].append(row['scan_time'][:16]) # trim to minute
            series['reachable'].append(row['reachable'])
            series['latency_ms'].append(row['latency_ms'])
            series['risk_score'].append(row['risk_score'])
            series['risk_level'].append(row['risk_level'])
            series['clearnet_leaks'].append(row['clearnet_leaks'])
            series['script_count'].append(row['script_count'])
            try:
                hdr_count = len(json.loads(row['security_headers_present'] or '[]'))
            except Exception:
                hdr_count = 0
            series['sec_header_count'].append(hdr_count)
            series['canary_valid'].append(row['canary_valid'])

        return JSONResponse(series) # type: ignore

 # Full scan JSON for a single scan
    @app.get('/api/scan/{scan_id}')
    async def get_scan_detail(scan_id: int) -> JSONResponse: # type: ignore
        with get_db(db_path) as conn:
            row = conn.execute('SELECT full_json FROM scans WHERE id = ?', (scan_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail='Scan not found') # type: ignore
        try:
            data = json.loads(row['full_json'])
        except Exception:
            data = {}
        return JSONResponse(data) # type: ignore

 # Update site metadata (tags, notes, category)
    @app.patch('/api/sites/{host:path}')
    async def update_site(host: str, body: dict[str, Any]) -> JSONResponse: # type: ignore
        host = host.strip('/')
        allowed = {'tags', 'notes', 'category'}
        updates = {k: v for k, v in body.items() if k in allowed}
        if not updates:
            raise HTTPException(status_code=400, detail='No valid fields to update') # type: ignore
        set_clause = ', '.join(f'{k} = ?' for k in updates)
        with get_db(db_path) as conn:
            conn.execute(
                f'UPDATE sites SET {set_clause} WHERE host = ?',
                list(updates.values()) + [host]
            )
        return JSONResponse({'ok': True, 'updated': list(updates.keys())}) # type: ignore

 # Ingest via file upload
    @app.post('/api/ingest')
    async def ingest_upload(file: UploadFile = File(...)) -> JSONResponse: # type: ignore
        try:
            content = await file.read()
            raw: dict[str, Any] = json.loads(content.decode('utf-8'))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f'Failed to parse file: {e}') # type: ignore

        try:
            reports, batch_id = normalize_mnemosyne_json(raw)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) # type: ignore

        ingested = 0
        skipped  = 0
        ingested_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        msgs: list[str] = []

        init_db(db_path)
        with get_db(db_path) as conn:
            for report in reports:
                ok, msg = ingest_report(conn, report, batch_id)
                if ok:
                    ingested += 1
                else:
                    skipped += 1
                msgs.append(msg)

        if batch_id:
            with get_db(db_path) as conn:
                # compute aggregates from what was just inserted
                agg = conn.execute('''
                    SELECT COUNT(*) as n,
                        SUM(reachable) as reach,
                        SUM(blacklisted) as bl,
                        AVG(risk_score) as avg_risk,
                        AVG(latency_ms) as avg_lat,
                        AVG(json_array_length(security_headers_present)) as avg_hdrs
                    FROM scans WHERE batch_id = ?
                ''', (batch_id,)).fetchone()
                conn.execute('''
                    INSERT OR REPLACE INTO batches
                    (batch_id, ingested_at, source_file, total_reports, reachable_count,
                    blacklisted_count, avg_risk_score, avg_latency_ms, avg_sec_headers)
                    VALUES (?,?,?,?,?,?,?,?,?)
                ''', (
                    batch_id, ingested_at, file.filename or 'upload',
                    agg['n'], agg['reach'] or 0, agg['bl'] or 0,
                    agg['avg_risk'] or 0.0, agg['avg_lat'], agg['avg_hdrs'] or 0.0,
                ))

        return JSONResponse({ # type: ignore
            'ingested': ingested,
            'skipped': skipped,
            'messages': msgs[:50], # cap for large batches
        })
    
    @app.get('/api/batches')
    async def get_batches() -> JSONResponse: # type: ignore
        with get_db(db_path) as conn:
            rows = conn.execute(
                'SELECT * FROM batches ORDER BY ingested_at DESC LIMIT 10'
            ).fetchall()
        return JSONResponse({'batches': [dict(r) for r in rows]}) # type: ignore

 # Categories list
    @app.get('/api/categories')
    async def list_categories() -> JSONResponse: # type: ignore
        return JSONResponse({'categories': list(CATEGORY_KEYWORDS.keys())}) # type: ignore
    
    @app.get('/api/terminal/random')
    async def terminal_random() -> JSONResponse: # type: ignore
        with get_db(db_path) as conn:
            row = conn.execute('''
                SELECT host, page_title, last_risk_level, last_risk_score,
                       last_seen, uptime_pct, category
                FROM sites
                WHERE blacklisted = 0 AND uptime_pct > 50
                ORDER BY RANDOM() LIMIT 1
            ''').fetchone()
        if not row:
            return JSONResponse({'result': 'No qualifying sites found (need uptime > 50%, not blacklisted).'}) # type: ignore
        return JSONResponse({'result': dict(row)}) # type: ignore

    @app.get('/api/terminal/top5')
    async def terminal_top5() -> JSONResponse: # type: ignore
        with get_db(db_path) as conn:
            rows = conn.execute('''
                SELECT host, page_title, last_risk_level, last_risk_score,
                       uptime_pct, category
                FROM sites
                WHERE scans_reachable > 0
                AND last_risk_level IN ('CRITICAL','HIGH','MEDIUM')
                ORDER BY last_risk_score DESC LIMIT 5
            ''').fetchall()
        return JSONResponse({'results': [dict(r) for r in rows]}) # type: ignore

    @app.get('/api/terminal/stats')
    async def terminal_stats() -> JSONResponse: # type: ignore
        with get_db(db_path) as conn:
            sites = conn.execute('SELECT COUNT(*) FROM sites').fetchone()[0]
            scans = conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
            batches = conn.execute('SELECT COUNT(*) FROM batches').fetchone()[0]
            blacklist = conn.execute('SELECT COUNT(*) FROM sites WHERE blacklisted=1').fetchone()[0]
            canary = conn.execute('SELECT COUNT(*) FROM sites WHERE canary_valid=1').fetchone()[0]
            high = conn.execute("SELECT COUNT(*) FROM sites WHERE last_risk_level IN ('HIGH','CRITICAL')").fetchone()[0]
            db_size = db_path.stat().st_size if db_path.exists() else 0
        return JSONResponse({ # type: ignore
            'sites': sites, 'scans': scans, 'batches': batches,
            'blacklisted': blacklist, 'canary_valid': canary,
            'high_risk': high, 'db_path': str(db_path),
            'db_size_mb': round(db_size / 1024 / 1024, 2),
        })

    @app.get('/api/terminal/view-site')
    async def terminal_view_site(host: str = Query('')) -> JSONResponse: # type: ignore
        if not host:
            return JSONResponse({'error': 'No host specified'}) # type: ignore
        with get_db(db_path) as conn:
            site = conn.execute('SELECT * FROM sites WHERE host = ?', (host,)).fetchone()
            if not site:
                return JSONResponse({'error': f'Host not found: {host}'}) # type: ignore
            scans = conn.execute(
                'SELECT scan_time, reachable, latency_ms, risk_level, risk_score, blacklisted, has_canary, canary_valid FROM scans WHERE host = ? ORDER BY scan_time DESC LIMIT 20',
                (host,)
            ).fetchall()
        return JSONResponse({'site': dict(site), 'scans': [dict(s) for s in scans]}) # type: ignore

    @app.get('/api/terminal/id-nulls')
    async def terminal_id_nulls() -> JSONResponse: # type: ignore
        with get_db(db_path) as conn:
            rows = conn.execute('''
                SELECT s.host, s.first_seen, s.category
                FROM sites s
                LEFT JOIN scans sc ON s.id = sc.site_id
                WHERE sc.id IS NULL
            ''').fetchall()
        return JSONResponse({'results': [dict(r) for r in rows]}) # type: ignore

    @app.delete('/api/terminal/delete-site')
    async def terminal_delete_site(host: str = Query('')) -> JSONResponse: # type: ignore
        if not host:
            return JSONResponse({'error': 'No host specified'}) # type: ignore
        with get_db(db_path) as conn:
            site = conn.execute('SELECT id FROM sites WHERE host = ?', (host,)).fetchone()
            if not site:
                return JSONResponse({'error': f'Host not found: {host}'}) # type: ignore
            site_id = site['id']
            scans_deleted = conn.execute('SELECT COUNT(*) FROM scans WHERE site_id = ?', (site_id,)).fetchone()[0]
            conn.execute('DELETE FROM scans WHERE site_id = ?', (site_id,))
            conn.execute('DELETE FROM sites WHERE id = ?', (site_id,))
        return JSONResponse({'ok': True, 'host': host, 'scans_deleted': scans_deleted}) # type: ignore
    
    @app.get('/api/journal')
    async def journal_load() -> JSONResponse: # type: ignore
        journal_path = db_path.parent / 'khaeos_journal.json'
        if journal_path.exists():
            try:
                data = json.loads(journal_path.read_text(encoding='utf-8'))
                return JSONResponse(data) # type: ignore
            except Exception:
                pass
        return JSONResponse({'version': 1, 'vpX': 0, 'vpY': 0, 'vpZ': 1, # type: ignore
                             'strokes': [], 'boxes': [], 'connectors': [], 'nextId': 1})

    @app.post('/api/journal')
    async def journal_save(body: dict[str, Any]) -> JSONResponse: # type: ignore
        journal_path = db_path.parent / 'khaeos_journal.json'
        journal_path.write_text(json.dumps(body), encoding='utf-8')
        return JSONResponse({'ok': True}) # type: ignore

    return app


# CLI
def parse_args() -> tuple[Path, Path | None, bool]:
    '''Returns (db_path, ingest_path_or_None, serve_after_ingest).'''
    args = sys.argv[1:]
    db_path = DEFAULT_DB
    ingest_path: Path | None = None
    serve = '--serve' in args

    if '-h' in args or '--help' in args:
        print(__doc__)
        sys.exit(0)

    if '--db' in args:
        idx = args.index('--db')
        try:
            db_path = Path(args[idx + 1])
        except IndexError:
            sys.exit(f'{R}[ERROR] --db requires a path argument.{RESET}')

    if '--ingest' in args:
        idx = args.index('--ingest')
        try:
            ingest_path = Path(args[idx + 1])
        except IndexError:
            sys.exit(f'{R}[ERROR] --ingest requires a file path argument.{RESET}')

    return db_path, ingest_path, serve


def main() -> int:
    if not _fastapi_available:
        print(f'{R}[ERROR] FastAPI and uvicorn are required:{RESET}')
        print(f'  pip install fastapi uvicorn\n')
        return 1

    db_path, ingest_path, serve_after = parse_args()

    print(BANNER)
    print(DIVIDER)

    init_db(db_path)
    print(f'  {DIM}Database  :{RESET} {db_path}')

 # Ingest mode
    if ingest_path is not None:
        print(f'\n  {DIM}Ingesting :{RESET} {ingest_path}\n')
        ingested, skipped, errors = ingest_file(ingest_path, db_path)
        print()
        print(f'{DIVIDER}')
        print(f'  {G}Ingested : {ingested}{RESET}')
        if skipped:
            print(f'  {DIM}Skipped  : {skipped} (duplicates){RESET}')
        for e in errors:
            print(f'  {R}Error    : {e}{RESET}')
        print()

        if not serve_after:
            print(f'{DIM}  Run without --ingest to start the UI server.{RESET}')
            print(f'{DIM}  Or use --ingest <file> --serve to do both.\n{RESET}')
            return 0

 # Server mode
    app = create_app(db_path)

    url = f'http://{DEFAULT_HOST}:{DEFAULT_PORT}'
    print(f'\n  {G}Khaeos starting on {url}{RESET}')
    print(f'  {DIM}Press Ctrl+C to stop.{RESET}\n')
    print(DIVIDER)

    def open_browser() -> None:
        import time as _time
        _time.sleep(1.2)
        webbrowser.open(url)

    threading.Thread(target=open_browser, daemon=True).start()

    uvicorn.run(app, host=DEFAULT_HOST, port=DEFAULT_PORT, log_level='warning') # type: ignore
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f'\n\n{DIM}[Khaeos stopped]{RESET}\n')
        sys.exit(0)