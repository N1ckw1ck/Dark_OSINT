#!/usr/bin/env python3

# Please Read Below
'''
d_mnemosyne.py is a .onion Hidden Service Recon & Safety Scanner

Pre visit analysis of Tor hidden services. Fetches only raw HTTP/HTML
over a SOCKS5 Tor circuit — no browser, no JavaScript execution, no
images, no cookies. This is a means of assessing a .onion address 
before any direct interaction, to inform you of site status and possible risks.

Checks performed (all passive / static analysis):
  • Reachability and HTTP response metadata
  • Security headers (CSP, HSTS, X-Frame-Options, etc.)
  • Redirect chain analysis (clearnet redirect is red flag)
  • Script tag enumeration and inline JS detection
  • External resource leakage (images, fonts, iframes loading off .onion)
  • Form detection (fields, action endpoints, methods)
  • Fingerprinting vectors in static HTML (canvas, WebRTC hints, WebGL)
  • Well-known file probing: canary.txt, pgp.txt, security.txt, robots.txt
  • PGP canary verification via gpg (if canary and key both present)
  • Server header and technology fingerprinting
  • Clearnet reference detection (links to non-.onion domains)
  • Weighted passive risk score

Usage:
  python d_mnemosyne.py [--save] [--debug]
  python d_mnemosyne.py --batch <url_list.txt>

    --batch <file>  Batch mode: 
        Read .onion URLs from a text file (one per line).
        Runs a sequential scan of all targets over a single Tor session.
        More URLs means it will take longer.
        Output is a grouped summary report. JSON (--save) produces a
        single consolidated file instead of per-target files.
        Generate the input file with: python d_erebus.py --save-j

Dependencies:
  pip install requests[socks] stem beautifulsoup4 python-gnupg
  Tor binary must be installed (tor or tor-browser-bundle)
  gpg binary required for canary PGP verification

Tor daemon:
  This tool will attempt to launch a managed Tor process via stem.
  If Tor is already running on 127.0.0.1:9050, it will use that instead.
  Install Tor: https://www.torproject.org/download/

Pretty safe but still use with caution.
For authorized research and investigative use only.
'''

from __future__ import annotations

import os
import re
import sys
import json
import time
import shutil
import socket
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse, urljoin
import hashlib
import requests # type: ignore
from bs4 import BeautifulSoup # type: ignore

# Optional: stem for managed Tor process
try:
    import stem # pyright: ignore[reportMissingTypeStubs]
    import stem.process # type: ignore
    import stem.control # type: ignore
    from stem import Signal # type: ignore
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False # type: ignore

# Optional: python-gnupg for canary verification
try:
    import gnupg # type: ignore
    GNUPG_AVAILABLE = True
except ImportError:
    GNUPG_AVAILABLE = False # type: ignore


# Constants
BANNER = '''
                                                             
██▄  ▄██ ▄▄  ▄▄ ▄▄▄▄▄ ▄▄   ▄▄  ▄▄▄   ▄▄▄▄ ▄▄ ▄▄ ▄▄  ▄▄ ▄▄▄▄▄ 
██ ▀▀ ██ ███▄██ ██▄▄  ██▀▄▀██ ██▀██ ███▄▄ ▀███▀ ███▄██ ██▄▄  
██    ██ ██ ▀██ ██▄▄▄ ██   ██ ▀███▀ ▄▄██▀   █   ██ ▀██ ██▄▄▄ 
                                                             
Μνημοσυνη
₲гⱥꮑꮏ ₥є гєⱥđұ гєꮥøʉгꞓє

.oni̸on H̵i̸ddĕn Servi̙ce Re̺connaí̦ssance
'''

DIVIDER = '─' * 62

TOR_SOCKS_HOST = '127.0.0.1'
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051

# Tor circuit rotation: wait this many seconds after NEWNYM before next request
NEWNYM_DELAY = 1

# Request settings — conservative for .onion latency
REQUEST_TIMEOUT = 40 # .onion services can be very slow
CRAWL_DELAY = 2 # seconds between page fetches

# Security headers to check for
SECURITY_HEADERS: list[str] = [
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'Permissions-Policy',
    'X-XSS-Protection',
]

# Well-known files to probe
WELL_KNOWN_PATHS: list[tuple[str, str]] = [
    ('/canary.txt', 'Warrant canary'),
    ('/pgp.txt', 'PGP public key'),
    ('/.well-known/pgp-key.txt', 'PGP public key (well-known)'),
    ('/security.txt', 'Security policy'),
    ('/.well-known/security.txt', 'Security policy (well-known)'),
    ('/robots.txt', 'Robots exclusion file'),
    ('/sitemap.xml', 'Sitemap'),
]

# PGP block markers
PGP_END_MARKERS: tuple[str, ...] = (
    '-----END PGP PUBLIC KEY BLOCK-----',
    '-----END PGP SIGNED MESSAGE-----',
    '-----END PGP SIGNATURE-----',
)

# Fingerprinting vector patterns in static HTML
FINGERPRINT_PATTERNS: list[tuple[str, str]] = [
    (r'<canvas', 'Canvas element (potential fingerprinting vector)'),
    (r'navigator\.webdriver', 'WebDriver detection attempt'),
    (r'navigator\.plugins', 'Plugin enumeration (fingerprinting)'),
    (r'navigator\.languages', 'Language fingerprinting'),
    (r'screen\.width|screen\.height|screen\.colorDepth', 'Screen dimension fingerprinting'),
    (r'webgl|WebGLRenderingContext', 'WebGL (GPU fingerprinting vector)'),
    (r'AudioContext|webkitAudioContext', 'AudioContext (audio fingerprinting)'),
    (r'RTCPeerConnection|webkitRTCPeerConnection', 'WebRTC (potential IP leak)'),
    (r'window\.crypto\.getRandomValues', 'Crypto API access'),
    (r'Intl\.DateTimeFormat|Date\.prototype\.toLocaleString', 'Timezone fingerprinting'),
    (r'navigator\.getBattery|BatteryManager', 'Battery API (fingerprinting)'),
    (r'document\.cookie', 'Cookie access in script'),
    (r'localStorage|sessionStorage', 'Local/session storage access'),
    (r'indexedDB', 'IndexedDB access'),
    (r'SharedWorker|ServiceWorker', 'Worker threads'),
]

# ANSI styling
R = '\033[91m'
G = '\033[92m'
Y = '\033[93m'
B = '\033[94m'
C = '\033[96m'
W = '\033[97m'
DIM = '\033[2m'
BOLD = '\033[1m'
RESET = '\033[0m'


# Dataclasses
@dataclass
class TorStatus:
    managed: bool # True if we launched the process, False if using existing
    running: bool
    socks_port: int
    control_available: bool
    tor_version: str

@dataclass
class ReachabilityResult:
    reachable: bool
    status_code: int | None
    latency_ms: float | None
    redirect_chain: list[str]
    final_url: str
    clearnet_redirect: bool # Any redirect to non-.onion = major red flag
    content_type: str
    content_length: str
    error: str

@dataclass
class ReputationResult:
    checked: bool
    blacklisted: bool
    error: str

@dataclass
class HeaderAnalysis:
    raw_headers: dict[str, str]
    server: str
    powered_by: str
    security_headers_present: list[str]
    security_headers_missing: list[str]
    interesting_headers: dict[str, str] # Non-standard headers worth noting
    csp_value: str
    csp_issues: list[str]

@dataclass
class WellKnownFile:
    path: str
    description: str
    found: bool
    status_code: int | None
    content: str # Raw content, truncated
    content_length: int

@dataclass
class CanaryVerification:
    canary_found: bool
    pgp_key_found: bool
    verification_attempted: bool
    signature_valid: bool | None
    key_fingerprint: str
    signing_fingerprint: str
    fingerprint_match: bool
    timestamp: str
    uid: str
    error: str

@dataclass
class ScriptAnalysis:
    total_script_tags: int
    inline_scripts: int # <script>...</script> with content
    external_scripts: list[str] # src= URLs
    external_scripts_onion: list[str] # src= pointing to .onion
    external_scripts_clearnet: list[str] # src= pointing to clearnet — very bad
    inline_event_handlers: int # onclick=, onload=, etc.
    javascript_hrefs: int # javascript: in href
    fingerprint_vectors: list[str] # matched patterns from FINGERPRINT_PATTERNS
    noscript_tags: int

@dataclass
class ExternalResourceLeak:
    tag: str
    attribute: str
    url: str
    is_clearnet: bool

@dataclass
class ResourceAnalysis:
    total_external_resources: int
    clearnet_leaks: list[ExternalResourceLeak] # Loading from clearnet = deanonymization risk
    onion_resources: list[ExternalResourceLeak]
    iframes: list[str]
    clearnet_links: list[str] # <a href> pointing to clearnet
    onion_links: list[str] # <a href> pointing to .onion addresses

@dataclass
class FormAnalysis:
    total_forms: int
    forms: list[dict[str, Any]] # Each: {action, method, fields: [...]}
    has_login_form: bool
    has_search_form: bool
    has_file_upload: bool
    actions_clearnet: list[str] # Form action pointing to clearnet

@dataclass
class TechFingerprint:
    web_server: str
    cms_hints: list[str]
    framework_hints: list[str]
    generator_meta: str
    language_hints: list[str]
    other: list[str]

@dataclass
class RiskScore:
    score: int
    level: str # LOW / MEDIUM / HIGH / CRITICAL
    flags: list[str]

@dataclass
class OnionReport:
    target: str
    scan_time: str
    tor: TorStatus
    reachability: ReachabilityResult
    reputation: ReputationResult | None
    headers: HeaderAnalysis | None
    well_known: list[WellKnownFile]
    canary: CanaryVerification | None
    scripts: ScriptAnalysis | None
    resources: ResourceAnalysis | None
    forms: FormAnalysis | None
    tech: TechFingerprint | None
    risk: RiskScore | None
    page_title: str
    raw_html_length: int


# Helpers
def print_divider() -> None:
    print(DIVIDER)

def print_section(title: str) -> None:
    print(f'\n{B}{BOLD}[ {title} ]{RESET}')
    print_divider()

def print_field(label: str, value: str, color: str = W) -> None:
    print(f'  {DIM}{label:<32}{RESET}{color}{value}{RESET}')

def print_flag(label: str, present: bool, good_when_present: bool = True) -> None:
    if present:
        color = G if good_when_present else R
        status = 'Present'
    else:
        color = R if good_when_present else G
        status = 'Missing'
    print_field(label, status, color)

def is_onion(url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    return host.endswith('.onion') or '.onion' in host

def is_clearnet(url: str) -> bool:
    if not url or url.startswith('#') or url.startswith('javascript:'):
        return False
    parsed = urlparse(url)
    if not parsed.netloc:
        return False
    return not parsed.netloc.endswith('.onion')

def validate_onion_address(address: str) -> str:
    '''Normalize and validate a .onion address. Returns cleaned URL.'''
    address = address.strip()
    if not address.startswith('http://') and not address.startswith('https://'):
        address = 'http://' + address
    parsed = urlparse(address)
    host = parsed.netloc
    if not host.endswith('.onion'):
        sys.exit(f'\n{R}[ERROR] "{host}" is not a .onion address.{RESET}\n')
    return address

def truncate(text: str, max_len: int = 200) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f'... [{len(text) - max_len} chars truncated]'


# Tor management
def check_tor_running() -> bool:
    '''Check if a Tor SOCKS proxy is already listening on the expected port.'''
    try:
        s = socket.create_connection((TOR_SOCKS_HOST, TOR_SOCKS_PORT), timeout=3)
        s.close()
        return True
    except Exception:
        return False

def launch_tor_process() -> tuple[Any, TorStatus]:
    '''
    Use stem to launch a managed Tor process.
    Returns (process_handle, TorStatus).
    process_handle is None if we are using an existing daemon.
    '''
    if not STEM_AVAILABLE:
        sys.exit(
            f'\n{R}[ERROR] stem is not installed. Install with: pip install stem{RESET}\n'
            f'        Or start Tor manually: tor --SocksPort 9050\n'
        )

    tor_binary = shutil.which('tor')
    if not tor_binary:
        sys.exit(
            f'\n{R}[ERROR] Tor binary not found on PATH.{RESET}\n'
            f'        Install Tor: https://www.torproject.org/download/\n'
            f'        On Debian/Ubuntu: sudo apt install tor\n'
            f'        On macOS: brew install tor\n'
        )

    if check_tor_running():
        print(f'  {G}Existing Tor daemon detected on port {TOR_SOCKS_PORT} — using it.{RESET}')
        tor_version = 'unknown (existing daemon)'
        try:
            with stem.control.Controller.from_port(port=TOR_CONTROL_PORT) as ctrl: # type:ignore
                ctrl.authenticate() # type: ignore
                tor_version = ctrl.get_version().version_str # type: ignore
        except Exception:
            pass
        return None, TorStatus(
            managed=False,
            running=True,
            socks_port=TOR_SOCKS_PORT,
            control_available=False,
            tor_version=tor_version, # type: ignore
        )

    print(f'  {DIM}Launching Tor via stem ({tor_binary})...{RESET}')
    try:
        tor_process = stem.process.launch_tor_with_config( # type: ignore
            config={
                'SocksPort': str(TOR_SOCKS_PORT),
                'ControlPort': str(TOR_CONTROL_PORT),
                'DataDirectory': tempfile.mkdtemp(prefix='c_onion_tor_'),
                'Log': 'notice stderr',
                'CookieAuthentication': '1',
            },
            init_msg_handler=lambda _: None, # type: ignore Suppress Tor startup noise 
            timeout=90
        )

        tor_version = 'unknown'
        try:
            with stem.control.Controller.from_port(port=TOR_CONTROL_PORT) as ctrl:  # type: ignore
                ctrl.authenticate()  # type: ignore
                while True:
                    bootstrap: str = str(ctrl.get_info('status/bootstrap-phase'))  # type: ignore
                    if 'PROGRESS=100' in str(bootstrap):
                        break
                    time.sleep(1)
        except Exception:
            pass

        return tor_process, TorStatus( # type: ignore
            managed=True,
            running=True,
            socks_port=TOR_SOCKS_PORT,
            control_available=True,
            tor_version=tor_version, # type: ignore
        )
    except Exception as e:
        sys.exit(f'\n{R}[ERROR] Failed to launch Tor: {e}{RESET}\n')

def rotate_circuit() -> bool:
    '''
    Request a new Tor circuit via stem control port.
    Returns True if successful. Used between target scans.
    '''
    if not STEM_AVAILABLE:
        return False
    try:
        with stem.control.Controller.from_port(port=TOR_CONTROL_PORT) as ctrl: # type: ignore
            ctrl.authenticate() # type: ignore (chroot_path=data_dir) match auth pattern maybe? v.0.1.9 working without
            ctrl.signal(Signal.NEWNYM) # type: ignore
        time.sleep(NEWNYM_DELAY)
        return True
    except Exception as e:
        if '--debug' in sys.argv:
            print(f'  {DIM}Circuit rotation error: {e}{RESET}')
        return False

def build_tor_session() -> requests.Session:
    '''
    Build a requests.Session configured to route through Tor SOCKS5 proxy.
    No cookies, no redirect following by default.
    '''
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    proxies = {
        'http': f'socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}',
        'https': f'socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}',
    }
    session.proxies.update(proxies)
    session.cookies.clear()
    # socks5h: hostname resolution happens inside Tor (critical for .onion)
    return session

def tor_get(
    session: requests.Session,
    url: str,
    *,
    allow_redirects: bool = False,
    stream: bool = False,
) -> requests.Response:
    '''
    Perform a GET over Tor with hardened headers and timeouts.
    Explicitly avoids sending Accept-Encoding to prevent compressed binary responses.
    '''
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        # No Accept-Encoding: avoid compressed responses that BS4 cannot parse
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    return session.get(
        url,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
        allow_redirects=allow_redirects,
        stream=stream,
        verify=False, # Don't verify the SSL cert
    )


# Reachability check
def check_reachability(session: requests.Session, base_url: str) -> ReachabilityResult:
    '''
    Follow the redirect chain manually to detect clearnet redirects.
    A .onion site redirecting to a clearnet domain is a critical red flag.
    '''
    redirect_chain: list[str] = []
    current_url = base_url
    final_url = base_url
    clearnet_redirect = False
    latency_ms: float | None = None
    status_code: int | None = None
    content_type = 'N/A'
    content_length = 'N/A'
    error = ''

    try:
        start = time.monotonic()
        response = tor_get(session, current_url, allow_redirects=False)
        latency_ms = round((time.monotonic() - start) * 1000, 1)
        status_code = response.status_code
        content_type = response.headers.get('Content-Type', 'N/A')
        content_length = response.headers.get('Content-Length', 'N/A')

        # Manually follow redirects to inspect each hop
        max_redirects = 15 # Can be incremented accordingly
        hops = 0
        while response.is_redirect and hops < max_redirects:
            location = response.headers.get('Location', '')
            if not location:
                break
            redirect_chain.append(location)
            if is_clearnet(location):
                clearnet_redirect = True
            current_url = urljoin(current_url, location)
            response = tor_get(session, current_url, allow_redirects=False)
            status_code = response.status_code
            content_type = response.headers.get('Content-Type', content_type)
            content_length = response.headers.get('Content-Length', content_length)
            hops += 1

        final_url = current_url

        return ReachabilityResult(
            reachable=True,
            status_code=status_code,
            latency_ms=latency_ms,
            redirect_chain=redirect_chain,
            final_url=final_url,
            clearnet_redirect=clearnet_redirect,
            content_type=content_type,
            content_length=content_length,
            error='',
        )
    except requests.exceptions.ConnectTimeout:
        error = 'Connection timed out — service may be offline or circuit is slow'
    except requests.exceptions.ConnectionError as e:
        error = f'Connection error: {e}'
    except Exception as e:
        error = f'Unexpected error: {e}'

    return ReachabilityResult(
        reachable=False,
        status_code=None,
        latency_ms=latency_ms,
        redirect_chain=redirect_chain,
        final_url=final_url,
        clearnet_redirect=clearnet_redirect,
        content_type='N/A',
        content_length='N/A',
        error=error,
    )

def fetch_ahmia_blacklist(session: requests.Session) -> set[str]:
    '''
    Fetch and cache the full Ahmia blacklist at startup over Tor.
    Routed through Tor so no clearnet requests are associated with this tool.
    '''
    url = 'https://ahmia.fi/blacklist/banned/'
    try:
        response = session.get(url, timeout=REQUEST_TIMEOUT, verify=False,
                               headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
        return {line.strip().lower() for line in response.text.splitlines() if line.strip()}
    except Exception as e:
        if '--debug' in sys.argv:
            print(f'  {DIM}Ahmia fetch error: {e}{RESET}')
        return set()
    
def check_ahmia_blacklist(onion_host: str, blacklist: set[str]) -> ReputationResult:
    try:
        host = onion_host.lower().split('/')[0]
        host_hash = hashlib.md5(host.encode('utf-8')).hexdigest() # Ahmia stores MD5 hashes of the .onion address, not plaintext
        blacklisted = host_hash in blacklist
        checked = len(blacklist) > 0
        return ReputationResult(
            checked=checked,
            blacklisted=blacklisted,
            error='' if checked else 'Blacklist could not be fetched',
        )
    except Exception as e:
        return ReputationResult(
            checked=False,
            blacklisted=False,
            error=str(e),
        )

# Header analysis
def analyze_headers(response: requests.Response) -> HeaderAnalysis:
    raw: dict[str, str] = dict(response.headers)
    raw_lower = {k.lower(): v for k, v in raw.items()}

    server = raw_lower.get('server', 'Not disclosed')
    powered_by = raw_lower.get('x-powered-by', 'Not disclosed')
    csp_value = raw_lower.get('content-security-policy', '')

    present: list[str] = []
    missing: list[str] = []
    for h in SECURITY_HEADERS:
        if h.lower() in raw_lower:
            present.append(h)
        else:
            missing.append(h)

    # Pick out non-standard headers that reveal information
    interesting: dict[str, str] = {}
    standard_boring = {
        'content-type', 'content-length', 'date', 'connection',
        'transfer-encoding', 'cache-control', 'expires', 'pragma',
        'content-security-policy', 'strict-transport-security',
        'x-frame-options', 'x-content-type-options', 'referrer-policy',
        'permissions-policy', 'x-xss-protection', 'server', 'x-powered-by',
        'set-cookie', 'vary', 'etag', 'last-modified', 'accept-ranges',
    }
    for k, v in raw_lower.items():
        if k not in standard_boring and (k.startswith('x-') or k in ('via', 'alt-svc')):
            interesting[k] = v

    # CSP quality check
    csp_issues: list[str] = []
    if csp_value:
        csp_lower = csp_value.lower()
        if 'unsafe-inline' in csp_lower:
            csp_issues.append("'unsafe-inline' allows inline scripts/styles — defeats XSS protection")
        if 'unsafe-eval' in csp_lower:
            csp_issues.append("'unsafe-eval' allows eval() — significant XSS risk")
        if re.search(r'script-src\s+\*|default-src\s+\*', csp_lower):
            csp_issues.append('Wildcard (*) in script/default-src — any origin allowed')
        if 'http:' in csp_lower:
            csp_issues.append("'http:' scheme allowed — mixed content risk")
    else:
        csp_issues.append('CSP header absent')

    return HeaderAnalysis(
        raw_headers=raw,
        server=server,
        powered_by=powered_by,
        security_headers_present=present,
        security_headers_missing=missing,
        interesting_headers=interesting,
        csp_value=csp_value,
        csp_issues=csp_issues,
    )


# Well-known file probing
def probe_well_known(session: requests.Session, base_url: str) -> list[WellKnownFile]:
    '''
    Probe well-known paths. Fetches content for canary and PGP key paths.
    Uses HEAD for everything else unless content is needed.
    '''
    results: list[WellKnownFile] = []
    content_paths = {'/canary.txt', '/pgp.txt', '/.well-known/pgp-key.txt',
                     '/security.txt', '/.well-known/security.txt', '/robots.txt'}

    for path, description in WELL_KNOWN_PATHS:
        url = base_url.rstrip('/') + path
        try:
            if path in content_paths:
                response = tor_get(session, url, allow_redirects=True)
                content = response.text[:4096] if response.status_code == 200 else ''
                status = response.status_code
                content_length = len(response.content)
            else:
                response = session.head(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    proxies={
                        'http': f'socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}',
                        'https': f'socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}',
                    },
                    allow_redirects=True,
                )
                status = response.status_code
                content = ''
                content_length = int(response.headers.get('Content-Length', 0))

            results.append(WellKnownFile(
                path=path,
                description=description,
                found=status == 200,
                status_code=status,
                content=content,
                content_length=content_length,
            ))
        except Exception:
            results.append(WellKnownFile(
                path=path,
                description=description,
                found=False,
                status_code=None,
                content='',
                content_length=0,
            ))

    return results


# PGP canary verification (reuses pgp_verify.py logic)
def verify_canary(well_known: list[WellKnownFile], *, debug: bool) -> CanaryVerification | None:
    '''
    If both canary.txt and a PGP key are available, attempt verification.
    Isolates key import to a temporary keyring — same pattern as pgp_verify.py.
    Returns None if prerequisites are not met.
    '''
    if not GNUPG_AVAILABLE:
        return None

    gpg_binary = shutil.which('gpg') or shutil.which('gpg2')
    if not gpg_binary:
        return None

    # Find canary content
    canary_content = ''
    for wk in well_known:
        if wk.path == '/canary.txt' and wk.found and wk.content:
            canary_content = wk.content
            break

    if not canary_content:
        return None

    # Check if canary is clearsigned
    if '-----BEGIN PGP SIGNED MESSAGE-----' not in canary_content:
        return CanaryVerification(
            canary_found=True,
            pgp_key_found=False,
            verification_attempted=False,
            signature_valid=None,
            key_fingerprint='',
            signing_fingerprint='',
            fingerprint_match=False,
            timestamp='',
            uid='',
            error='Canary found but is not a PGP clearsigned message — cannot verify',
        )

    # Find PGP key
    pgp_key_content = ''
    for key_path in ['/pgp.txt', '/.well-known/pgp-key.txt']:
        for wk in well_known:
            if wk.path == key_path and wk.found and wk.content:
                if '-----BEGIN PGP PUBLIC KEY BLOCK-----' in wk.content:
                    pgp_key_content = wk.content
                    break
        if pgp_key_content:
            break

    if not pgp_key_content:
        return CanaryVerification(
            canary_found=True,
            pgp_key_found=False,
            verification_attempted=False,
            signature_valid=None,
            key_fingerprint='',
            signing_fingerprint='',
            fingerprint_match=False,
            timestamp='',
            uid='',
            error='Canary is PGP-signed but no public key found at /pgp.txt or /.well-known/pgp-key.txt',
        )

    # Verify in isolated temporary keyring
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chmod(tmpdir, 0o700)
            gpg: Any = gnupg.GPG(gnupghome=tmpdir) # type: ignore
            gpg.encoding = 'utf-8'

            import_result: Any = gpg.import_keys(pgp_key_content)
            if not import_result.count:
                return CanaryVerification(
                    canary_found=True,
                    pgp_key_found=True,
                    verification_attempted=True,
                    signature_valid=False,
                    key_fingerprint='',
                    signing_fingerprint='',
                    fingerprint_match=False,
                    timestamp='',
                    uid='',
                    error='Failed to import public key — key block may be malformed',
                )

            fingerprints: list[str] = import_result.fingerprints or []
            imported_fp = fingerprints[0] if fingerprints else ''

            asc_path = os.path.join(tmpdir, 'canary.asc')
            with open(asc_path, 'w', encoding='utf-8') as fh:
                fh.write(canary_content)
            with open(asc_path, 'rb') as fh:
                result: Any = gpg.verify_file(fh)

            valid = bool(result)
            sig_fp = str(getattr(result, 'fingerprint', '') or '')
            timestamp_raw = str(getattr(result, 'timestamp', '') or getattr(result, 'sig_timestamp', '') or '')
            uid = str(getattr(result, 'username', '') or '')

            # Format timestamp
            timestamp = ''
            if timestamp_raw:
                try:
                    dt = datetime.fromtimestamp(int(timestamp_raw), tz=timezone.utc)
                    timestamp = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                except Exception as e:
                    if '--debug' in sys.argv:
                        print(f'  {DIM}Timestamp formatting error: {e}{RESET}')
                    timestamp = timestamp_raw

            fp_match = bool(sig_fp and imported_fp and sig_fp.upper() == imported_fp.upper())

            return CanaryVerification(
                canary_found=True,
                pgp_key_found=True,
                verification_attempted=True,
                signature_valid=valid,
                key_fingerprint=imported_fp.upper(),
                signing_fingerprint=sig_fp.upper(),
                fingerprint_match=fp_match,
                timestamp=timestamp,
                uid=uid,
                error='' if valid else (str(getattr(result, 'status', '')) or 'Verification failed'),
            )
    except Exception as e:
        return CanaryVerification(
            canary_found=True,
            pgp_key_found=True,
            verification_attempted=True,
            signature_valid=False,
            key_fingerprint='',
            signing_fingerprint='',
            fingerprint_match=False,
            timestamp='',
            uid='',
            error=f'GPG error: {e}',
        )


# Static HTML analysis
def analyze_scripts(soup: BeautifulSoup, html: str) -> ScriptAnalysis:
    '''Enumerate all script tags and inline JS patterns. No execution.'''
    script_tags = soup.find_all('script')
    inline_scripts = 0
    external_scripts: list[str] = []
    external_scripts_onion: list[str] = []
    external_scripts_clearnet: list[str] = []

    for tag in script_tags:
        src = tag.get('src', '')
        if src:
            external_scripts.append(str(src))
            if is_onion(str(src)):
                external_scripts_onion.append(str(src))
            elif is_clearnet(str(src)):
                external_scripts_clearnet.append(str(src)) # Very bad
        elif tag.string and tag.string.strip():
            inline_scripts += 1

    # Inline event handlers on any element
    inline_handlers = 0
    event_attrs = [
        'onclick', 'onload', 'onmouseover', 'onsubmit', 'onchange',
        'onerror', 'onfocus', 'onblur', 'onkeyup', 'onkeydown',
    ]
    for tag in soup.find_all(True):
        for attr in event_attrs:
            if tag.get(attr):
                inline_handlers += 1

    # Javascript: hrefs
    js_hrefs = sum(
        1 for tag in soup.find_all('a', href=True)
        if str(tag.get('href', '')).strip().lower().startswith('javascript:')
    )

    # Fingerprinting vector detection in raw HTML
    fingerprint_vectors: list[str] = []
    for pattern, description in FINGERPRINT_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            fingerprint_vectors.append(description)

    noscript_tags = len(soup.find_all('noscript'))

    return ScriptAnalysis(
        total_script_tags=len(script_tags),
        inline_scripts=inline_scripts,
        external_scripts=external_scripts,
        external_scripts_onion=external_scripts_onion,
        external_scripts_clearnet=external_scripts_clearnet,
        inline_event_handlers=inline_handlers,
        javascript_hrefs=js_hrefs,
        fingerprint_vectors=fingerprint_vectors,
        noscript_tags=noscript_tags,
    )

def analyze_resources(soup: BeautifulSoup) -> ResourceAnalysis:
    '''
    Enumerate external resource references. Clearnet resources loaded by a
    .onion page will contact clearnet servers, deanonymizing the visitor.
    '''
    # Tag → attribute pairs that load external resources
    resource_checks: list[tuple[str, str]] = [
        ('img', 'src'),
        ('link', 'href'),
        ('script', 'src'),
        ('iframe', 'src'),
        ('audio', 'src'),
        ('video', 'src'),
        ('source', 'src'),
        ('embed', 'src'),
        ('object', 'data'),
    ]

    clearnet_leaks: list[ExternalResourceLeak] = []
    onion_resources: list[ExternalResourceLeak] = []
    iframes: list[str] = []
    clearnet_links: list[str] = []
    onion_links: list[str] = []

    total = 0

    for tag_name, attr in resource_checks:
        for tag in soup.find_all(tag_name):
            url = str(tag.get(attr, '') or '')
            if not url or url.startswith('data:') or url.startswith('#'):
                continue
            parsed = urlparse(url)
            if not parsed.netloc: # Relative URLs — skip
                continue
            total += 1
            leak = ExternalResourceLeak(
                tag=tag_name,
                attribute=attr,
                url=url,
                is_clearnet=is_clearnet(url),
            )
            if is_clearnet(url):
                clearnet_leaks.append(leak)
            elif is_onion(url):
                onion_resources.append(leak)
            if tag_name == 'iframe':
                iframes.append(url)

    # Link analysis
    for tag in soup.find_all('a', href=True):
        href = str(tag.get('href', '') or '')
        if not href or href.startswith('#') or href.startswith('javascript:'):
            continue
        parsed = urlparse(href)
        if not parsed.netloc:
            continue
        if is_clearnet(href):
            clearnet_links.append(href)
        elif is_onion(href):
            onion_links.append(href)

    return ResourceAnalysis(
        total_external_resources=total,
        clearnet_leaks=clearnet_leaks,
        onion_resources=onion_resources,
        iframes=iframes,
        clearnet_links=list(dict.fromkeys(clearnet_links)), # dedupe, preserve order
        onion_links=list(dict.fromkeys(onion_links)),
    )

def analyze_forms(soup: BeautifulSoup) -> FormAnalysis:
    '''Parse all forms: fields, methods, action endpoints.'''
    form_tags = soup.find_all('form')
    forms: list[dict[str, Any]] = []
    has_login = False
    has_search = False
    has_upload = False
    actions_clearnet: list[str] = []

    for form in form_tags:
        action = str(form.get('action', '') or '')
        method = str(form.get('method', 'GET')).upper()
        fields: list[dict[str, str]] = []

        for inp in form.find_all(['input', 'textarea', 'select']):
            field_type = str(inp.get('type', 'text')).lower()
            field_name = str(inp.get('name', '') or inp.get('id', '') or '')
            fields.append({'type': field_type, 'name': field_name})

            if field_type == 'password':
                has_login = True
            if field_type == 'file':
                has_upload = True
            if field_type == 'search' or 'search' in field_name.lower():
                has_search = True

        if action and is_clearnet(action):
            actions_clearnet.append(action)

        forms.append({'action': action, 'method': method, 'fields': fields})

    return FormAnalysis(
        total_forms=len(form_tags),
        forms=forms,
        has_login_form=has_login,
        has_search_form=has_search,
        has_file_upload=has_upload,
        actions_clearnet=actions_clearnet,
    )

def fingerprint_tech(soup: BeautifulSoup, headers: HeaderAnalysis | None) -> TechFingerprint:
    '''Fingerprint server technology from static HTML and headers.'''
    cms_hints: list[str] = []
    framework_hints: list[str] = []
    language_hints: list[str] = []
    other: list[str] = []
    web_server = 'Not disclosed'
    generator_meta = ''

    if headers:
        web_server = headers.server
        pb = headers.powered_by
        if pb != 'Not disclosed':
            language_hints.append(f'X-Powered-By: {pb}')
        for k, v in headers.interesting_headers.items():
            other.append(f'{k}: {v}')

    # Generator meta tag
    gen = soup.find('meta', attrs={'name': re.compile(r'generator', re.I)})
    if gen:
        generator_meta = str(gen.get('content', ''))

    html_text = str(soup)

    # CMS detection
    if '/wp-content/' in html_text or '/wp-includes/' in html_text:
        cms_hints.append('WordPress (path patterns)')
    if generator_meta:
        for cms in ('WordPress', 'Drupal', 'Joomla', 'Ghost', 'Hugo', 'Jekyll'):
            if cms.lower() in generator_meta.lower():
                cms_hints.append(f'{cms} (meta generator)')

    # Framework hints
    if '__NEXT_DATA__' in html_text:
        framework_hints.append('Next.js')
    if 'data-reactroot' in html_text:
        framework_hints.append('React')
    if 'ng-version' in html_text:
        framework_hints.append('Angular')
    if '__nuxt' in html_text:
        framework_hints.append('Nuxt.js')
    if '__gatsby' in html_text:
        framework_hints.append('Gatsby')

    # Language hints from HTML
    if 'php' in html_text.lower() and 'php' not in ' '.join(language_hints).lower():
        # Light signal — PHP errors or paths
        php_match = re.search(r'\.php[\?"\']', html_text)
        if php_match:
            language_hints.append('PHP (path patterns in HTML)')

    return TechFingerprint(
        web_server=web_server,
        cms_hints=cms_hints,
        framework_hints=framework_hints,
        generator_meta=generator_meta,
        language_hints=language_hints,
        other=other,
    )


# Risk scoring
def calculate_risk(
    reachability: ReachabilityResult,
    reputation: ReputationResult | None,
    headers: HeaderAnalysis | None,
    scripts: ScriptAnalysis | None,
    resources: ResourceAnalysis | None,
    forms: FormAnalysis | None,
    canary: CanaryVerification | None,
    well_known: list[WellKnownFile],
) -> RiskScore:
    '''
    Weighted passive risk score. Score caps at 100.
    Levels: 0-24 = LOW, 25-49 = MEDIUM, 50-74 = HIGH, 75+ = CRITICAL
    '''
    score = 0
    flags: list[str] = []

    if not reachability.reachable:
        return RiskScore(score=0, level='UNKNOWN', flags=['Service unreachable — no analysis possible'])

    # Clearnet redirect serious!
    if reachability.clearnet_redirect:
        score += 40
        flags.append('CRITICAL: Site redirects to a clearnet domain — deanonymization risk')

    # Clearnet resource leaks — deanonymization
    if resources and resources.clearnet_leaks:
        n = len(resources.clearnet_leaks)
        score += min(30, n * 10)
        flags.append(f'Site loads {n} resource(s) from clearnet — visitors may be deanonymized')

    # Clearnet form actions
    if forms and forms.actions_clearnet:
        score += 25
        flags.append(f'Form action(s) point to clearnet: {", ".join(forms.actions_clearnet[:2])}')

    # External scripts from clearnet
    if scripts and scripts.external_scripts_clearnet:
        n = len(scripts.external_scripts_clearnet)
        score += min(25, n * 12)
        flags.append(f'{n} script(s) loaded from clearnet origin(s) — critical deanonymization risk')

    # PGP canary issues
    if canary:
        if canary.canary_found and canary.verification_attempted:
            if canary.signature_valid is False:
                score += 20
                flags.append('Canary PGP signature INVALID — site may be compromised')
            elif canary.signature_valid and not canary.fingerprint_match:
                score += 15
                flags.append('Canary signed by a different key than published — possible key substitution')
        elif canary.canary_found and not canary.pgp_key_found:
            score += 5
            flags.append('Warrant canary found but no PGP key published — cannot verify authenticity')

    if reputation and reputation.checked and reputation.blacklisted:
        score += 50
        flags.append('CRITICAL: Address is on the Ahmia abuse blacklist')

    # Missing security headers
    if headers:
        missing_count = len(headers.security_headers_missing)
        if missing_count >= 5:
            score += 10
            flags.append(f'{missing_count} of {len(SECURITY_HEADERS)} security headers missing')
        elif missing_count >= 3:
            score += 5
            flags.append(f'{missing_count} of {len(SECURITY_HEADERS)} security headers missing')

        # CSP absent or weak
        if not headers.csp_value:
            score += 8
            flags.append('No Content-Security-Policy header')
        elif 'unsafe-inline' in headers.csp_value.lower():
            score += 4
            flags.append("CSP contains 'unsafe-inline'")

        # Server/tech disclosure
        if headers.server not in ('Not disclosed', 'N/A', ''):
            score += 3
            flags.append(f'Server software disclosed: {headers.server}')
        if headers.powered_by not in ('Not disclosed', 'N/A', ''):
            score += 3
            flags.append(f'Technology disclosed via X-Powered-By: {headers.powered_by}')

    # Script risk
    if scripts:
        if scripts.total_script_tags > 0:
            score += min(8, scripts.total_script_tags * 2)
            flags.append(f'{scripts.total_script_tags} script tag(s) present in HTML')
        if scripts.fingerprint_vectors:
            score += min(10, len(scripts.fingerprint_vectors) * 2)
            flags.append(f'{len(scripts.fingerprint_vectors)} fingerprinting vector(s) detected in static HTML')
        if scripts.inline_event_handlers > 0:
            score += min(5, scripts.inline_event_handlers)
            flags.append(f'{scripts.inline_event_handlers} inline event handler(s) (onclick, onload, etc.)')

    # Iframes
    if resources and resources.iframes:
        score += len(resources.iframes) * 3
        flags.append(f'{len(resources.iframes)} iframe(s) found')

    # No well-known files at all — low trust signal
    wk_found = sum(1 for wk in well_known if wk.found)
    if wk_found == 0:
        score += 5
        flags.append('No well-known files found (no canary, no security.txt, no PGP key)')

    score = min(score, 100)

    if score >= 75:
        level = 'CRITICAL'
    elif score >= 50:
        level = 'HIGH'
    elif score >= 25:
        level = 'MEDIUM'
    else:
        level = 'LOW'

    return RiskScore(score=score, level=level, flags=flags)


# Main scan orchestration
def run_scan(session: requests.Session, target_url: str, *, tor_status: TorStatus, debug: bool, ahmia_blacklist: set[str]) -> OnionReport:
    base_url = target_url.rstrip('/')
    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    print(f'\n{DIM}[1/9] Checking reachability...{RESET}')
    reachability = check_reachability(session, base_url)

    # Here so Ahmia blocklist check will work even if target is unreachable
    parsed_host = urlparse(target_url).netloc
    reputation = check_ahmia_blacklist(parsed_host, ahmia_blacklist)

    if not reachability.reachable:
        print(f'\n{R}  Service is not reachable: {reachability.error}{RESET}')
        return OnionReport(
            target=target_url,
            scan_time=scan_time,
            tor=tor_status,
            reachability=reachability,
            reputation=reputation,
            headers=None,
            well_known=[],
            canary=None,
            scripts=None,
            resources=None,
            forms=None,
            tech=None,
            risk=RiskScore(score=0, level='UNKNOWN', flags=['Service unreachable']),
            page_title='',
            raw_html_length=0,
        )
    
    print(f'{DIM}[2/9] Checking reputation blacklists...{RESET}')

    # Fetch root page once, reuse soup for all HTML analysis
    headers_result: HeaderAnalysis | None = None
    soup: BeautifulSoup | None = None
    html = ''
    page_title = ''
    raw_html_length = 0

    print(f'{DIM}[3/9] Fetching root page and analyzing headers...{RESET}')
    try:
        response = tor_get(session, reachability.final_url, allow_redirects=True)
        headers_result = analyze_headers(response)
        html = response.text
        raw_html_length = len(response.content)
        soup = BeautifulSoup(html, 'html.parser')
        title_tag = soup.find('title')
        page_title = title_tag.get_text(strip=True)[:200] if title_tag else ''
    except Exception as e:
        if debug:
            print(f'  {R}Root page fetch error: {e}{RESET}')

    print(f'{DIM}[4/9] Probing well-known files...{RESET}')
    well_known = probe_well_known(session, base_url)

    print(f'{DIM}[5/9] Verifying PGP canary...{RESET}')
    canary = verify_canary(well_known, debug=debug)

    scripts: ScriptAnalysis | None = None
    resources: ResourceAnalysis | None = None
    forms: FormAnalysis | None = None
    tech: TechFingerprint | None = None

    if soup is not None:
        print(f'{DIM}[6/9] Analyzing scripts and fingerprinting vectors...{RESET}')
        scripts = analyze_scripts(soup, html)

        print(f'{DIM}[7/9] Analyzing external resource references...{RESET}')
        resources = analyze_resources(soup)

        print(f'{DIM}[8/9] Analyzing forms...{RESET}')
        forms = analyze_forms(soup)

        print(f'{DIM}[9/9] Fingerprinting technology stack...{RESET}')
        tech = fingerprint_tech(soup, headers_result)
    else:
        print(f'  {Y}HTML parsing skipped — root page unavailable.{RESET}')

    risk = calculate_risk(reachability, reputation, headers_result, scripts, resources, forms, canary, well_known)

    return OnionReport(
        target=target_url,
        scan_time=scan_time,
        tor=tor_status,
        reachability=reachability,
        reputation=reputation,
        headers=headers_result,
        well_known=well_known,
        canary=canary,
        scripts=scripts,
        resources=resources,
        forms=forms,
        tech=tech,
        risk=risk,
        page_title=page_title,
        raw_html_length=raw_html_length,
    )


# Print report sections
def print_tor_section(tor: TorStatus) -> None:
    print_section('TOR STATUS')
    status_color = G if tor.running else R
    print_field('Status:', 'Running' if tor.running else 'Not running', status_color)
    print_field('Mode:', 'Managed (launched by tool)' if tor.managed else 'External daemon', DIM + W)
    print_field('SOCKS Port:', str(tor.socks_port))
    print_field('Version:', tor.tor_version, DIM + W)
    print_field('Control Port:', 'Available' if tor.control_available else 'Not available', DIM + W)

def print_reachability_section(r: ReachabilityResult) -> None:
    print_section('REACHABILITY')
    reach_color = G if r.reachable else R
    print_field('Reachable:', 'Yes' if r.reachable else 'No', reach_color)

    if r.status_code is not None:
        code_color = G if r.status_code < 400 else Y if r.status_code < 500 else R
        print_field('HTTP Status:', str(r.status_code), code_color)

    if r.latency_ms is not None:
        lat_color = G if r.latency_ms < 5000 else Y if r.latency_ms < 15000 else R
        print_field('Latency:', f'{r.latency_ms} ms', lat_color)

    print_field('Content-Type:', r.content_type)
    print_field('Content-Length:', r.content_length)

    print_field('Final URL:', r.final_url)

    if r.redirect_chain:
        print(f'\n  {DIM}Redirect chain:{RESET}')
        for hop in r.redirect_chain:
            hop_color = R if is_clearnet(hop) else Y
            flag = f'  {R}← CLEARNET REDIRECT{RESET}' if is_clearnet(hop) else ''
            print(f'    {hop_color}→ {hop}{RESET}{flag}')

    if r.clearnet_redirect:
        print(f'\n  {R}{BOLD}CRITICAL: This site redirects to a clearnet domain.{RESET}')
        print(f'  {R}Visiting this link in a browser could deanonymize you.{RESET}')

    if not r.reachable and r.error:
        print(f'\n  {Y}Error: {r.error}{RESET}')

def print_reputation_section(rep: ReputationResult) -> None:
    print_section('REPUTATION / BLACKLIST CHECK')
    print_field('Check performed:', 'Yes' if rep.checked else 'No')

    if not rep.checked:
        print(f'\n  {Y}Blacklist check failed: {rep.error}{RESET}')
        return

    if rep.blacklisted:
        print(f'\n  {R}{BOLD}WARNING: Address is on the Ahmia abuse blacklist.{RESET}')
        print(f'  {R}This address has been flagged for abusive or illegal content.{RESET}')
        print(f'  {R}Do not visit this address.{RESET}')
    else:
        print(f'\n  {G}Not found on Ahmia abuse blacklist.{RESET}')

def print_header_section(h: HeaderAnalysis, page_title: str) -> None:
    print_section('HTTP HEADERS & SERVER INFO')

    if page_title:
        print_field('Page Title:', page_title, C)

    print_field('Server:', h.server, Y if h.server != 'Not disclosed' else G)
    print_field('X-Powered-By:', h.powered_by, Y if h.powered_by != 'Not disclosed' else G)

    print(f'\n  {DIM}{"─" * 18} Security Headers {"─" * 12}{RESET}')
    for header in h.security_headers_present:
        print_field(f'  {header}:', 'Present', G)
    for header in h.security_headers_missing:
        print_field(f'  {header}:', 'Missing', R)

    if h.csp_value:
        print(f'\n  {DIM}CSP value:{RESET}')
        print(f'    {DIM}{truncate(h.csp_value, 160)}{RESET}')
    if h.csp_issues:
        for issue in h.csp_issues:
            print(f'    {Y}⚑ {issue}{RESET}')

    if h.interesting_headers:
        print(f'\n  {DIM}{"─" * 18} Notable Headers {"─" * 14}{RESET}')
        for k, v in h.interesting_headers.items():
            print(f'    {DIM}{k}: {W}{truncate(v, 80)}{RESET}')

def print_well_known_section(well_known: list[WellKnownFile]) -> None:
    print_section('WELL-KNOWN FILES')
    for wk in well_known:
        found_color = G if wk.found else DIM + W
        status_str = f'[{wk.status_code}]' if wk.status_code else '[N/A]'
        print(f'  {found_color}{status_str:<7}{RESET}  {W}{wk.path:<40}{RESET}  {DIM}{wk.description}{RESET}')

        if wk.found and wk.content:
            preview = wk.content.strip()[:120].replace('\n', ' ')
            print(f'         {DIM}↳ {preview}{RESET}')

def print_canary_section(canary: CanaryVerification) -> None:
    print_section('WARRANT CANARY VERIFICATION')

    print_flag('Canary found:', canary.canary_found)
    print_flag('PGP key found:', canary.pgp_key_found)
    print_flag('Verification attempted:', canary.verification_attempted)

    if not canary.verification_attempted:
        print(f'\n  {Y}{canary.error}{RESET}')
        return

    if canary.signature_valid is True:
        print(f'\n  {G}{BOLD}✓ CANARY SIGNATURE VALID — message is authentic{RESET}')
    elif canary.signature_valid is False:
        print(f'\n  {R}{BOLD}✗ CANARY SIGNATURE INVALID — possible compromise or tampering{RESET}')
    else:
        print(f'\n  {Y}Verification result unknown{RESET}')

    print()
    if canary.key_fingerprint:
        print_field('Published key fingerprint:', ' '.join(
            canary.key_fingerprint[i:i+4] for i in range(0, len(canary.key_fingerprint), 4)
        ), DIM + W)
    if canary.signing_fingerprint:
        match_color = G if canary.fingerprint_match else R
        print_field('Signing key fingerprint:', ' '.join(
            canary.signing_fingerprint[i:i+4] for i in range(0, len(canary.signing_fingerprint), 4)
        ), match_color)
        if not canary.fingerprint_match:
            print(f'\n  {R}[!] Signing key does NOT match published key — key substitution possible{RESET}')

    if canary.uid:
        print_field('Key identity (UID):', canary.uid)
    if canary.timestamp:
        print_field('Signature timestamp:', canary.timestamp)

    if canary.error and canary.signature_valid is False:
        print(f'\n  {DIM}GPG status: {canary.error}{RESET}')

def print_script_section(scripts: ScriptAnalysis) -> None:
    print_section('SCRIPT ANALYSIS (STATIC)')

    script_color = R if scripts.total_script_tags > 0 else G
    print_field('Total script tags:', str(scripts.total_script_tags), script_color)
    print_field('Inline scripts:', str(scripts.inline_scripts))
    print_field('External scripts:', str(len(scripts.external_scripts)))
    print_field('  → .onion sources:', str(len(scripts.external_scripts_onion)), DIM + W)

    if scripts.external_scripts_clearnet:
        print_field('  → CLEARNET sources:', str(len(scripts.external_scripts_clearnet)), R + BOLD)
        for src in scripts.external_scripts_clearnet:
            print(f'    {R}↳ {truncate(src, 80)}{RESET}')

    handler_color = Y if scripts.inline_event_handlers > 0 else G
    print_field('Inline event handlers:', str(scripts.inline_event_handlers), handler_color)
    print_field('javascript: hrefs:', str(scripts.javascript_hrefs),
                Y if scripts.javascript_hrefs else G)
    print_field('Noscript tags:', str(scripts.noscript_tags))

    if scripts.fingerprint_vectors:
        print(f'\n  {DIM}{"─" * 18} Fingerprinting Vectors {"─" * 10}{RESET}')
        for vec in scripts.fingerprint_vectors:
            print(f'    {Y}⚑ {vec}{RESET}')
    else:
        print(f'\n    {G}No fingerprinting patterns detected in static HTML.{RESET}')

def print_resource_section(resources: ResourceAnalysis) -> None:
    print_section('EXTERNAL RESOURCE ANALYSIS')
    print_field('Total external resources:', str(resources.total_external_resources))
    print_field('Iframes:', str(len(resources.iframes)), Y if resources.iframes else G)
    print_field('Clearnet links (href):', str(len(resources.clearnet_links)),
                Y if resources.clearnet_links else G)
    print_field('.onion links (href):', str(len(resources.onion_links)))

    if resources.clearnet_leaks:
        print(f'\n  {R}{BOLD}DEANONYMIZATION RISK: Resources loaded from clearnet{RESET}')
        for leak in resources.clearnet_leaks:
            print(f'    {R}↳ <{leak.tag} {leak.attribute}="{leak.url}">{RESET}')
    else:
        print(f'\n    {G}No clearnet resource leaks detected.{RESET}')

    if resources.clearnet_links:
        print(f'\n  {DIM}{"─" * 18} Clearnet Links (href) {"─" * 10}{RESET}')
        for link in resources.clearnet_links[:15]:
            print(f'    {Y}{link}{RESET}')
        if len(resources.clearnet_links) > 15:
            print(f'    {DIM}... and {len(resources.clearnet_links) - 15} more{RESET}')

    if resources.onion_links:
        print(f'\n  {DIM}{"─" * 18} .onion Links Found {"─" * 13}{RESET}')
        for link in resources.onion_links[:15]:
            print(f'    {C}{link}{RESET}')
        if len(resources.onion_links) > 15:
            print(f'    {DIM}... and {len(resources.onion_links) - 15} more{RESET}')

def print_form_section(forms: FormAnalysis) -> None:
    print_section('FORM ANALYSIS')
    print_field('Total forms:', str(forms.total_forms))
    print_flag('Login form detected:', forms.has_login_form, good_when_present=False)
    print_flag('File upload form:', forms.has_file_upload, good_when_present=False)
    print_flag('Search form:', forms.has_search_form)

    if forms.actions_clearnet:
        print(f'\n  {R}{BOLD}CRITICAL: Form action(s) point to clearnet domains{RESET}')
        for action in forms.actions_clearnet:
            print(f'    {R}↳ {action}{RESET}')

    if forms.forms:
        print(f'\n  {DIM}{"─" * 18} Forms Detail {"─" * 18}{RESET}')
        for i, form in enumerate(forms.forms, 1):
            action_str = form.get('action', '') or '(no action)'
            method_str = form.get('method', 'GET')
            action_color = R if is_clearnet(action_str) else W
            print(f'  {DIM}Form {i}:{RESET} {action_color}{truncate(action_str, 60)}{RESET}  {DIM}[{method_str}]{RESET}')
            for field_info in form.get('fields', []):
                fname = field_info.get('name', '(unnamed)')
                ftype = field_info.get('type', 'text')
                type_color = R if ftype == 'password' else DIM
                print(f'    {type_color}  {ftype:<12} {fname}{RESET}')

def print_tech_section(tech: TechFingerprint) -> None:
    print_section('TECHNOLOGY FINGERPRINT')
    print_field('Web Server:', tech.web_server, Y if tech.web_server != 'Not disclosed' else G)

    if tech.generator_meta:
        print_field('Generator Meta:', tech.generator_meta)
    if tech.cms_hints:
        for hint in tech.cms_hints:
            print_field('CMS Hint:', hint, Y)
    if tech.framework_hints:
        for hint in tech.framework_hints:
            print_field('Framework:', hint, Y)
    if tech.language_hints:
        for hint in tech.language_hints:
            print_field('Language Hint:', hint, Y)
    if tech.other:
        print(f'\n  {DIM}{"─" * 18} Additional Headers {"─" * 12}{RESET}')
        for item in tech.other:
            print(f'    {DIM}{item}{RESET}')

def print_risk_section(risk: RiskScore) -> None:
    print_section('PASSIVE RISK ASSESSMENT')

    level_colors = {
        'LOW': G,
        'MEDIUM': Y,
        'HIGH': R,
        'CRITICAL': R + BOLD,
        'UNKNOWN': DIM + W,
    }
    color = level_colors.get(risk.level, W)
    print_field('Risk Level:', risk.level, color)
    print_field('Score (0-100):', str(risk.score), color)

    if risk.flags:
        print(f'\n  {DIM}{"─" * 18} Risk Factors {"─" * 18}{RESET}')
        for flag in risk.flags:
            flag_color = R if any(w in flag for w in ('CRITICAL', 'INVALID', 'clearnet', 'deanon')) else Y
            print(f'    {flag_color}⚑ {flag}{RESET}')
    else:
        print(f'\n    {G}No significant risk factors detected.{RESET}')

def print_full_report(report: OnionReport) -> None:
    print('''

                R̯̣ͅECO̵̡͝NNAI̴̛͇͓̣͇͓͍̜̖̜͡S̢̢̘͖̘̗̘̻̕SA̲̰͔N̤̭̳CȨ̷͍͉̪̤̟̘͈̘̦͟ REP̞͙̰O̸̷̧̩̯̤ͭ͊͘͜͏̙̩͔͉͉̝ͦRT

''')
    print(f'\n{DIM}{"─" * 62}{RESET}')
    print(f'{DIM}  Target    : {report.target}{RESET}')
    print(f'{DIM}  Scan time : {report.scan_time}{RESET}')
    print(f'{DIM}  HTML size : {report.raw_html_length} bytes{RESET}')

    print_tor_section(report.tor)
    print_reachability_section(report.reachability)
    if report.reputation:
        print_reputation_section(report.reputation)

    if report.headers:
        print_header_section(report.headers, report.page_title)

    print_well_known_section(report.well_known)

    if report.canary:
        print_canary_section(report.canary)

    if report.scripts:
        print_script_section(report.scripts)

    if report.resources:
        print_resource_section(report.resources)

    if report.forms:
        print_form_section(report.forms)

    if report.tech:
        print_tech_section(report.tech)

    if report.risk:
        print_risk_section(report.risk)

    print(f'\n{DIVIDER}\n')

def _serialize_report(report: OnionReport) -> dict[str, Any]:
    return {
        'scan_time': report.scan_time,
        'target': report.target,
        'tor': asdict(report.tor),
        'reachability': asdict(report.reachability),
        'reputation': asdict(report.reputation) if report.reputation else None,
        'headers': asdict(report.headers) if report.headers else None,
        'well_known': [asdict(wk) for wk in report.well_known],
        'canary': asdict(report.canary) if report.canary else None,
        'scripts': asdict(report.scripts) if report.scripts else None,
        'resources': {
            'total_external_resources': report.resources.total_external_resources,
            'clearnet_leaks': [asdict(l) for l in report.resources.clearnet_leaks],
            'onion_resources': [asdict(l) for l in report.resources.onion_resources],
            'iframes': report.resources.iframes,
            'clearnet_links': report.resources.clearnet_links,
            'onion_links': report.resources.onion_links,
        } if report.resources else None,
        'forms': asdict(report.forms) if report.forms else None,
        'tech': asdict(report.tech) if report.tech else None,
        'risk': asdict(report.risk) if report.risk else None,
        'page_title': report.page_title,
        'raw_html_length': report.raw_html_length,
    }

# Save
def save_report(report: OnionReport) -> None:
    data = _serialize_report(report)
    parsed = urlparse(report.target)
    host = parsed.netloc or parsed.path
    safe_name = re.sub(r'[^\w.-]', '_', host)
    filename = f'Mnemosyne_{safe_name}.json'
    with open(filename, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    print(f'{G}  Report saved → {filename}{RESET}\n')

def save_batch_report(reports: list[OnionReport], url_source: str) -> str:
    blacklisted = [r for r in reports if r.reputation and r.reputation.blacklisted]
    clearnet_redirects = [r for r in reports if r.reachability.clearnet_redirect]
    unreachable = [r for r in reports if not r.reachability.reachable]
    critical_high = [
        r for r in reports
        if r.reachability.reachable
        and r.risk is not None
        and r.risk.level in ('CRITICAL', 'HIGH')
        and not (r.reputation and r.reputation.blacklisted)
        and not r.reachability.clearnet_redirect
    ]
    medium_low = [
        r for r in reports
        if r.reachability.reachable
        and r.risk is not None
        and r.risk.level in ('MEDIUM', 'LOW')
        and not (r.reputation and r.reputation.blacklisted)
        and not r.reachability.clearnet_redirect
    ]
    unknown = [
        r for r in reports
        if (r.risk is None or r.risk.level == 'UNKNOWN')
        and r.reachability.reachable
    ]
    data: dict[str, Any] = {
        'batch_scan_time': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'url_source': url_source,
        'total_targets': len(reports),
        'summary': {
            'blacklisted': len(blacklisted),
            'clearnet_redirects': len(clearnet_redirects),
            'unreachable': len(unreachable),
            'critical_or_high_risk': len(critical_high),
            'medium_or_low_risk': len(medium_low),
            'unknown': len(unknown),
        },
        'groups': {
            'blacklisted': [r.target for r in blacklisted],
            'clearnet_redirects': [r.target for r in clearnet_redirects],
            'unreachable': [r.target for r in unreachable],
            'critical_or_high_risk': [r.target for r in critical_high],
            'medium_or_low_risk': [r.target for r in medium_low],
            'unknown': [r.target for r in unknown],
        },
        'reports': [_serialize_report(r) for r in reports],
    }
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'Mnemosyne_batch_{timestamp}.json'
    with open(filename, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    return filename


def print_batch_summary(reports: list[OnionReport]) -> None:
    blacklisted = [r for r in reports if r.reputation and r.reputation.blacklisted]
    clr_redirects = [r for r in reports if r.reachability.clearnet_redirect]
    unreachable = [r for r in reports if not r.reachability.reachable]
    critical_high = [
        r for r in reports
        if r.reachability.reachable
        and r.risk is not None
        and r.risk.level in ('CRITICAL', 'HIGH')
        and not (r.reputation and r.reputation.blacklisted)
        and not r.reachability.clearnet_redirect
    ]
    medium_low = [
        r for r in reports
        if r.reachability.reachable
        and r.risk is not None
        and r.risk.level in ('MEDIUM', 'LOW')
        and not (r.reputation and r.reputation.blacklisted)
        and not r.reachability.clearnet_redirect
    ]
    unknown = [
        r for r in reports
        if (r.risk is None or r.risk.level == 'UNKNOWN')
        and r.reachability.reachable
    ]

    print(f'\n\nBATCH SCAN SUMMARY\n')
    print(DIVIDER)
    print(f'  Total targets scanned : {BOLD}{W}{len(reports)}{RESET}')

    def _risk_color(level: str) -> str:
        return {
            'CRITICAL': R + BOLD,
            'HIGH': R,
            'MEDIUM': Y,
            'LOW': G,
            'UNKNOWN': DIM + W,
        }.get(level, W)

    def _print_group(
        title: str,
        color: str,
        group: list[OnionReport],
        show_risk: bool = False,
        show_error: bool = False,
        show_flags: bool = False,
    ) -> None:
        print(f'\n{color}{BOLD}  ● {title}  [{len(group)} target(s)]{RESET}')
        print(f'  {DIVIDER}')
        if not group:
            print(f'    {DIM}None.{RESET}')
            return
        for r in group:
            risk_level = r.risk.level if r.risk else 'UNKNOWN'
            risk_score = r.risk.score if r.risk else 0
            rc = _risk_color(risk_level)
            print(f'    {color}→{RESET}  {C}{r.target}{RESET}')
            if r.page_title:
                print(f'       {DIM}Title  : {W}{r.page_title}{RESET}')
            if r.reachability.reachable and r.reachability.status_code is not None:
                lat = f'{r.reachability.latency_ms} ms' if r.reachability.latency_ms else 'N/A'
                print(f'       {DIM}Status : {W}{r.reachability.status_code}{RESET}  {DIM}Latency: {W}{lat}{RESET}')
            if show_risk and r.risk:
                print(f'       {DIM}Risk   : {rc}{risk_level} ({risk_score}/100){RESET}')
            if show_error and not r.reachability.reachable and r.reachability.error:
                print(f'       {DIM}Error  : {Y}{r.reachability.error}{RESET}')
            if show_flags and r.risk and r.risk.flags:
                for flag in r.risk.flags[:3]:
                    flag_color = R if any(w in flag for w in ('CRITICAL', 'INVALID', 'clearnet', 'deanon', 'blacklist')) else Y
                    print(f'       {flag_color}⚑ {flag}{RESET}')
                if len(r.risk.flags) > 3:
                    print(f'       {DIM}  … {len(r.risk.flags) - 3} more flag(s) — see JSON{RESET}')
            print()

    _print_group('AHMIA ABUSE BLACKLIST', R, blacklisted, show_risk=True, show_flags=True)
    _print_group('CLEARNET REDIRECT  ⚠  DEANONYMIZATION RISK', R, clr_redirects, show_risk=True)
    _print_group('UNREACHABLE / OFFLINE', Y, unreachable, show_error=True)
    _print_group('HIGH / CRITICAL RISK  (reachable)', R, critical_high, show_risk=True, show_flags=True)
    _print_group('MEDIUM / LOW RISK  (reachable)', G, medium_low, show_risk=True, show_flags=True)
    if unknown:
        _print_group('UNKNOWN RISK', DIM + W, unknown)
    print(f'\n{DIVIDER}\n')


def run_batch(url_file: str, *, debug: bool, save: bool) -> int:
    from pathlib import Path as _Path
    p = _Path(url_file)
    if not p.exists():
        sys.exit(f'\n{R}[ERROR] Batch URL file not found: {url_file}{RESET}\n')

    raw_lines = p.read_text(encoding='utf-8').splitlines()
    targets: list[str] = []
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            targets.append(validate_onion_address(line))
        except SystemExit:
            print(f'{Y}[WARN] Skipping invalid address: {line}{RESET}')

    if not targets:
        sys.exit(f'\n{R}[ERROR] No valid .onion URLs found in {url_file}.{RESET}\n')

    print(BANNER)
    print(f'Batch mode — {len(targets)} target(s) loaded from: {url_file}')
    print('Pre-visit .onion safety scanner. Fetches only raw HTTP/HTML over Tor.')
    print('No browser, no JS execution, no images.\n')
    print_divider()
    print()

    if not STEM_AVAILABLE:
        print(f'{Y}[WARN] stem not installed — Tor must be running manually on port {TOR_SOCKS_PORT}{RESET}\n')
    if not GNUPG_AVAILABLE:
        print(f'{Y}[WARN] python-gnupg not installed — canary verification disabled{RESET}\n')
    elif not (shutil.which('gpg') or shutil.which('gpg2')):
        print(f'{Y}[WARN] gpg binary not found — canary verification disabled{RESET}\n')

    print(f'{DIM}Initializing Tor...{RESET}')
    tor_process, tor_status = launch_tor_process()
    print(f'  {G}Tor ready.{RESET} (version: {tor_status.tor_version})\n')

    session = build_tor_session()

    print(f'{DIM}Fetching Ahmia blacklist over Tor...{RESET}')
    ahmia_blacklist = fetch_ahmia_blacklist(session)
    if ahmia_blacklist:
        print(f'  {G}{len(ahmia_blacklist)} entries loaded.{RESET}\n')
    else:
        print(f'  {Y}Blacklist unavailable — blacklist checks will be skipped.{RESET}\n')

    print_divider()
    print(f'\n{BOLD}Starting batch scan: {len(targets)} target(s){RESET}\n')

    reports: list[OnionReport] = []

    try:
        for i, target_url in enumerate(targets, 1):
            if i > 1 and tor_status.control_available:
                print(f'{DIM}  Rotating circuit...{RESET}', end=' ', flush=True)
                ok = rotate_circuit()
                print(f'{G}done.{RESET}' if ok else f'{Y}skipped.{RESET}')

            print(f'{B}[{i}/{len(targets)}]{RESET} {C}{target_url}{RESET}', end=' ', flush=True)

            report = run_scan(
                session,
                target_url,
                tor_status=tor_status,
                debug=debug,
                ahmia_blacklist=ahmia_blacklist,
            )
            reports.append(report)

            risk_level = report.risk.level if report.risk else 'UNKNOWN'
            level_colors: dict[str, str] = {
                'CRITICAL': R + BOLD, 'HIGH': R, 'MEDIUM': Y, 'LOW': G, 'UNKNOWN': DIM + W,
            }
            lc = level_colors.get(risk_level, W)

            if not report.reachability.reachable:
                print(f'  {Y}OFFLINE{RESET}')
            elif report.reputation and report.reputation.blacklisted:
                print(f'  {R}{BOLD}BLACKLISTED{RESET}  {lc}{risk_level}{RESET}')
            elif report.reachability.clearnet_redirect:
                print(f'  {R}CLEARNET REDIRECT{RESET}  {lc}{risk_level}{RESET}')
            else:
                score = report.risk.score if report.risk else 0
                print(f'  {lc}{risk_level} ({score}/100){RESET}')

    finally:
        if tor_process is not None:
            print(f'\n{DIM}Shutting down managed Tor process...{RESET}')
            try:
                tor_process.kill() # type: ignore[union-attr]
                print(f'  {G}Tor process shut down cleanly.{RESET}')
            except Exception as e:
                print(f'  {Y}Warning: could not shut down Tor: {e}{RESET}')

    print_batch_summary(reports)

    if not save:
        save_choice = input(f'{C}> Save batch report to JSON? [y/N]: {RESET}').strip().lower()
        if save_choice == 'y':
            save = True

    if save:
        filename = save_batch_report(reports, url_source=url_file)
        print(f'{G}  Batch report saved → {filename}{RESET}\n')

    levels = [r.risk.level for r in reports if r.risk]
    if 'CRITICAL' in levels:
        return 3
    if 'HIGH' in levels:
        return 2
    if 'MEDIUM' in levels:
        return 1
    return 0


# Entry point
def main() -> int:
    debug = '--debug' in sys.argv
    save = '--save' in sys.argv
    if '--batch' in sys.argv:
        idx = sys.argv.index('--batch')
        try:
            batch_file = sys.argv[idx + 1]
        except IndexError:
            sys.exit(f'\n{R}[ERROR] --batch requires a file path argument.{RESET}\n'
                     f'        Usage: python d_mnemosyne.py --batch <url_list.txt>\n')
        return run_batch(batch_file, debug=debug, save=save)

    print(BANNER)
    print('Pre-visit .onion safety scanner. Fetches only raw HTTP/HTML over Tor.')
    print('No browser, no JS execution, no images. Somewhat safe for security research.\n')
    print_divider()
    print()

    # Dependency checks
    if not STEM_AVAILABLE:
        print(f'{Y}[WARN] stem not installed — install with: pip install stem{RESET}')
        print(f'{Y}       Tor must be running manually on port {TOR_SOCKS_PORT}{RESET}\n')

    if not GNUPG_AVAILABLE:
        print(f'{Y}[WARN] python-gnupg not installed — canary verification disabled{RESET}')
        print(f'{Y}       Install with: pip install python-gnupg{RESET}\n')
    elif not (shutil.which('gpg') or shutil.which('gpg2')):
        print(f'{Y}[WARN] gpg binary not found — canary verification disabled{RESET}\n')

    # Target input
    print(f'{Y}Enter target .onion address:{RESET}')
    raw_target = input(f'{C}> URL (e.g. http://example.onion): {RESET}').strip()
    if not raw_target:
        sys.exit(f'\n{R}[ERROR] No target provided.{RESET}\n')
    target_url = validate_onion_address(raw_target)

    # Tor setup
    print(f'\n{DIM}Initializing Tor...{RESET}')
    tor_process, tor_status = launch_tor_process()

    print(f'  {G}Tor ready.{RESET} (version: {tor_status.tor_version})\n')

    # New circuit for clean identity
    if tor_status.control_available:
        print(f'{DIM}Requesting fresh circuit for this target...{RESET}')
        if rotate_circuit():
            print(f'  {G}New circuit established.{RESET}\n')
        else:
            print(f'  {Y}Circuit rotation unavailable — continuing with existing circuit.{RESET}\n')

    # Build session and scan
    session = build_tor_session()

    print(f'{DIM}Fetching Ahmia blacklist over Tor...{RESET}')
    ahmia_blacklist = fetch_ahmia_blacklist(session)
    if ahmia_blacklist:
        print(f'  {G}{len(ahmia_blacklist)} entries loaded.{RESET}\n')
    else:
        print(f'  {Y}Blacklist unavailable — check will be skipped.{RESET}\n')

    print_divider()
    print(f'\n{BOLD}Scanning: {C}{target_url}{RESET}')
    print()

    try:
        report = run_scan(session, target_url, tor_status=tor_status, debug=debug, ahmia_blacklist=ahmia_blacklist)
    finally:
        if tor_process is not None:
            print(f'\n{DIM}Shutting down managed Tor process...{RESET}')
            try:
                tor_process.kill() # type: ignore[union-attr]
                print(f'  {G}Tor process shut down cleanly.{RESET}')
            except Exception as e:
                print(f'  {Y}Warning: could not shut down Tor process: {e}{RESET}')
                print(f'  {Y}You may need to kill it manually.{RESET}')

    print_full_report(report)

    if not save:
        save_choice = input(f'{C}> Save report to current directory? [y/N]: {RESET}').strip().lower()
        if save_choice == 'y':
            save = True

    if save:
        save_report(report)

    # Return exit code based on risk level
    risk_level = report.risk.level if report.risk else 'UNKNOWN'
    if risk_level == 'CRITICAL':
        return 3
    if risk_level == 'HIGH':
        return 2
    if risk_level == 'MEDIUM':
        return 1
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f'\n\n{DIM}[Aborted]{RESET}')
        sys.exit(130)