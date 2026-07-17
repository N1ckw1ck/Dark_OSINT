#!/usr/bin/env python3
'''
Dark Web Search Aggregator

Queries multiple .onion search indexes simultaneously over a managed Tor
circuit to find mentions of a search term across the dark web. Results
are aggregated, deduplicated, and ranked for threat intelligence and
security research use cases.

Current search indexes:
  • Ahmia - ahmia.fi .onion mirror (most structured / reliable)
  • Torch - classic Tor search engine (uncensored) (unreliable)
  • Tor66 - broad dark web index
  • notevil - supplementary index (uncensored) (unreliable)
  • Amnesia - another broad dark web index

PLEASE NOTE: There is no guarantee that the .onion links below are working or legitimate.
The Ahmia link is most likely safe, but the others are hit or miss.
Assume every search is logged, and that you may be getting manipulated results!
Use d_hemera.py and d_mnemosyne.py to your advantage.

If you are getting connection errors (SOCKSHTTPConnectionPool()), the .onion 
link hardcoded below for that search engine is likely not working. You can 
update these values in INDEXES with working links.

Deduplication:
  • Same host, different paths = grouped
  • Known link farm blocklist
  • Branched path display: groups results under their canonical host

Output:
  • CLI: rich formatted table, top 50 results shown
  • JSON: full result set, pass --save-j or --no-save or it will prompt you on every run
  • HTML: full result set, pass --save-h or --no-save or it will prompt you on every run

Usage:
  python d_erebus.py [--pages N] [--debug] [--no-save]

  --pages <N>    Pages to fetch per index (1-10, default 1) e.g. python d_erebus.py --pages 5
  --save-j     Save results to JSON, skips HTML prompt
  --save-h     Save full results to HTML, skips JSON prompt
  --no-save    Skip all save prompts
  --debug      Show verbose error output

Dependencies:
  pip install requests[socks] stem beautifulsoup4 rich

Tor:
  This tool launches a managed Tor process via stem, or uses an existing
  Tor daemon on 127.0.0.1:9050 if one is already running.
  Install Tor: https://www.torproject.org/download/
  On Debian/Ubuntu: sudo apt install tor
  On macOS: brew install tor

Notes:
  All requests are routed through Tor using socks5h (DNS resolved inside Tor).
  No clearnet requests are made. Circuit is rotated between each index.
  Do not enter PII as search terms! It may well become public information.

Use a VPN!
Assume searches are logged and you are being fingerprinted.
For authorized research and investigative use only.
'''

from __future__ import annotations

import re
import sys
import json
import time
import shutil
import socket
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse, quote_plus

import requests # type: ignore
from bs4 import BeautifulSoup # type: ignore

try:
    import stem # pyright: ignore[reportMissingTypeStubs]
    import stem.process # type: ignore
    import stem.control # type: ignore
    from stem import Signal # type: ignore
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False # type: ignore

try:
    from rich.console import Console # type: ignore
    from rich.table import Table # type: ignore
    from rich import box # type: ignore
    from rich.text import Text # type: ignore
    from rich.panel import Panel # type: ignore
    RICH_AVAILABLE = True
except ImportError:
    Console = None # type: ignore
    Table = None # type: ignore
    box = None # type: ignore
    Text = None # type: ignore
    Panel = None # type: ignore
    RICH_AVAILABLE = False # type: ignore


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

# Constants
BANNER = f'''{R}
n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n n 
u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u u 
m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m m 
b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b b 
e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e e 
r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r 
0 1 0 0 0 1 0 1 0 1 0 1 0 0 1 0 0 1 0 0 0 1 0 1 0 1 0 0 0 0 1 0 0 1 0 1 0 1 0 1 0 1 0 1 0 0 1 1 
{RESET}
Ερεβος
₱єєг ɨᴨŧø ŧħє ₫ⱥгꝁᴨєꮥꮥ

Dar̘k̲͋ ͛Web Se͔ar͡ch̨ Aggre̟g͢ator

'''

DIVIDER = '─' * 62

TOR_SOCKS_HOST = '127.0.0.1'
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
NEWNYM_DELAY = 2 # seconds to wait after NEWNYM signal
REQUEST_TIMEOUT = 60 # .onion services are slow
INTER_PAGE_DELAY = 1 # seconds between paginated requests
MAX_PAGES = 10
DEFAULT_PAGES = 1
CLI_RESULT_LIMIT = 50

# Known link farm blocklist
# Add any .onion hostnames (without http://) of sites that are bloating the results
LINK_FARM_BLOCKLIST: set[str] = {
    # darkweblinks.com mirrors — add their .onion addresses here as you find them
    'dwltorbltw3tdjskxn23j2mwz2f4q25j4ninl5bdvttiy4xb6cqzikid.onion',
}

# Search index definitions
@dataclass
class IndexConfig:
    name: str
    base_url: str
    search_path: str # Path to append, use {query} and {page} placeholders
    result_selector: str
    title_selector: str 
    url_selector: str
    snippet_selector: str
    paginated: bool = True

INDEXES: list[IndexConfig] = [
    IndexConfig(
        name='Ahmia',
        base_url='http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion', # This one is pretty solid
        search_path='/search/?q={query}',
        result_selector='li.result',
        title_selector='h4',
        url_selector='cite',
        snippet_selector='p',
        paginated=False, # All results on one page
    ),
    IndexConfig(
        name='Torch', # Flaky
        base_url='http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion', # May have to change or just might not work
        search_path='/cgi-bin/omega/omega',
        result_selector='tr td:nth-of-type(2)', # actually why
        title_selector='b a',
        url_selector='b a',
        snippet_selector='small',
        paginated=True,
    ),
    IndexConfig(
        name='Tor66',
        base_url='http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion',
        search_path='/search?q={query}',
        result_selector='b', # Results are in <b><a href='...'> elements
        title_selector='a',
        url_selector='a',
        snippet_selector='', # Snippet follows the <br> after the <b> block — handled in scraper
        paginated=True,
    ),
    IndexConfig(
        name='notevil', # Somewhat flaky
        base_url='http://notevil2ebbr5xjww6nryjta7bycbriyi2vh7an3wcuovlznvobykmad.onion', # http://notevilmtxf25uw7tskqxj6njlpebyrmlrerfv5hc4tuq7c7hilbyiqd.onion things change
        search_path='/search?search={query}',
        result_selector='a.custom-result-item',
        title_selector='h2.custom-result-title',
        url_selector='a',
        snippet_selector='p.custom-result-description',
        paginated=True,
    ),
    IndexConfig(
        name='Amnesia', # Pretty solid
        base_url='http://amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion',
        search_path='/search?query={query}',
        result_selector='div.results',
        title_selector='h2 a',
        url_selector='h2 a',
        snippet_selector='p.site_desc',
        paginated=True,
    ),
]

# Dataclasses
@dataclass
class TorStatus:
    managed: bool
    running: bool
    socks_port: int
    control_available: bool
    tor_version: str

@dataclass
class RawResult:
    title: str
    url: str
    snippet: str
    source_index: str
    page: int

@dataclass
class BranchedResult:
    '''A canonical .onion host with one or more URL paths seen for it.'''
    canonical_host: str
    paths: list[str]
    title: str
    snippet: str
    source_indexes: list[str]
    is_link_farm: bool

@dataclass
class SearchRun:
    query: str
    run_time: str
    pages_per_index: int
    total_raw: int
    total_after_dedup: int
    indexes_queried: list[str]
    indexes_failed: list[str]
    results: list[BranchedResult]

# Tor management
def check_tor_running() -> bool:
    try:
        s = socket.create_connection((TOR_SOCKS_HOST, TOR_SOCKS_PORT), timeout=3)
        s.close()
        return True
    except Exception:
        return False

def launch_tor_process(debug: bool = False) -> tuple[Any, TorStatus]:
    if not STEM_AVAILABLE:
        sys.exit(
            f'\n{R}[ERROR] stem is not installed. Install with: pip install stem{RESET}\n'
            '        Or start Tor manually and re-run.\n'
        )

    tor_binary = shutil.which('tor')
    if not tor_binary:
        sys.exit(
            f'\n{R}[ERROR] Tor binary not found on PATH.{RESET}\n'
            '        Install Tor: https://www.torproject.org/download/\n'
            '        On Debian/Ubuntu: sudo apt install tor\n'
            '        On macOS: brew install tor\n'
        )

    if check_tor_running():
        print(f'  {G}Existing Tor daemon detected on port {TOR_SOCKS_PORT} — using it.{RESET}')
        tor_version = 'unknown (existing daemon)'
        control_available = False
        
        try:
            with stem.control.Controller.from_port(port=TOR_CONTROL_PORT) as ctrl: # type: ignore
                ctrl.authenticate() # type: ignore
                tor_version = str(ctrl.get_version().version_str) # type: ignore
                control_available = True
        except Exception:
            pass
        return None, TorStatus(
            managed=False,
            running=True,
            socks_port=TOR_SOCKS_PORT,
            control_available=control_available,
            tor_version=tor_version,
        )

    print(f'  {DIM}Launching Tor via stem ({tor_binary})...{RESET}')
    try:
        tor_process = stem.process.launch_tor_with_config( # type: ignore
            config={
                'SocksPort': str(TOR_SOCKS_PORT),
                'ControlPort': str(TOR_CONTROL_PORT),
                'DataDirectory': tempfile.mkdtemp(prefix='d_search_tor_'),
                'Log': 'notice stderr',
                'CookieAuthentication': '1',
            },
            init_msg_handler=lambda _: None, # type: ignore
            timeout=90,
        )

        tor_version = 'unknown'
        try:
            with stem.control.Controller.from_port(port=TOR_CONTROL_PORT) as ctrl: # type: ignore
                ctrl.authenticate() # type: ignore
                while True:
                    bootstrap: str = str(ctrl.get_info('status/bootstrap-phase')) # type: ignore
                    if 'PROGRESS=100' in bootstrap:
                        break
                    time.sleep(1)
                tor_version = str(ctrl.get_version()) # type: ignore
        except Exception:
            pass

        return tor_process, TorStatus( # type: ignore
            managed=True,
            running=True,
            socks_port=TOR_SOCKS_PORT,
            control_available=True,
            tor_version=tor_version,
        )
    except Exception as e:
        sys.exit(f'\n{R}[ERROR] Failed to launch Tor: {e}{RESET}\n')

def rotate_circuit(debug: bool = False) -> bool:
    if not STEM_AVAILABLE:
        return False
    try:
        with stem.control.Controller.from_port(port=TOR_CONTROL_PORT) as ctrl: # type: ignore
            ctrl.authenticate() # type: ignore
            ctrl.signal(Signal.NEWNYM) # type: ignore
        time.sleep(NEWNYM_DELAY)
        return True
    except Exception as e:
        if debug:
            print(f'  {DIM}Circuit rotation error: {e}{RESET}')
        return False

def build_tor_session() -> requests.Session:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    proxies = {
        'http': f'socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}',
        'https': f'socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}',
    }
    session.proxies.update(proxies)
    session.cookies.clear()
    return session

def tor_get(session: requests.Session, url: str) -> requests.Response:
    '''
    GET over Tor with hardened headers.
    No Accept-Encoding to avoid compressed binary responses BS4 cannot parse.
    '''
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    }
    return session.get(
        url,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
        verify=False,
    )

def tor_post(session: requests.Session, url: str, data: dict[str, str]) -> requests.Response:
    '''
    POST over Tor with hardened headers.
    Can be used for indexes that paginate via form submission (e.g. Amnesia).
    '''
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    return session.post(
        url,
        headers=headers,
        data=data,
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
        verify=False,
    )


# URL / dedup helpers
_ONION_RE = re.compile(r'[a-z2-7]{16,56}\.onion', re.IGNORECASE)

def extract_onion_host(url: str) -> str | None:
    '''
    Return the canonical .onion hostname from a URL, or None if not a valid
    .onion URL. Strips scheme, port, auth, and trailing dots.
    '''
    if not url:
        return None
    # Some indexes return bare hostnames without scheme
    if not url.startswith('http'):
        url = 'http://' + url
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        # Strip port if present
        if ':' in host:
            host = host.split(':')[0]
        if host.endswith('.onion'):
            return host
    except Exception:
        pass
    # Fallback: regex match anywhere in the string
    m = _ONION_RE.search(url.lower())
    return m.group(0) if m else None

def canonical_url_path(url: str) -> str:
    '''
    Extract the path component from a URL, normalised for grouping.
    Returns '/' for root or unparseable URLs.
    '''
    if not url.startswith('http'):
        url = 'http://' + url
    try:
        parsed = urlparse(url)
        path = parsed.path or '/'
        if parsed.query:
            path = path + '?' + parsed.query
        return path
    except Exception:
        return '/'

def is_link_farm(host: str) -> bool:
    return host.lower() in LINK_FARM_BLOCKLIST

def check_onion_reachable(session: requests.Session, base_url: str, debug: bool) -> bool:
    try:
        resp = tor_get(session, base_url + '/')
        return resp.status_code < 500
    except requests.exceptions.Timeout:
        if debug:
            print(f'  {DIM}Reachability check timed out: {base_url}{RESET}')
        return False
    except Exception as e:
        if debug:
            print(f'  {DIM}Reachability check failed: {e}{RESET}')
        return False

def fetch_ahmia_search_token(session: requests.Session, base_url: str, debug: bool) -> tuple[str, str] | None:
    '''
    Ahmia embeds a hidden CSRF-style token in its homepage search form.
    Must be included in search requests or the query is ignored.
    Returns (param_name, param_value) or None on failure.
    '''
    try:
        resp = tor_get(session, base_url + '/')
        if debug:
            print(f'  {DIM}[Ahmia] cookies after homepage: {dict(session.cookies)}{RESET}')
        soup = BeautifulSoup(resp.text, 'html.parser')
        hidden = soup.select_one('form#searchForm input[type=hidden]')
        if hidden:
            name = hidden.get('name', '')
            value = hidden.get('value', '')
            if name and value:
                return str(name), str(value)
        if debug:
            print(f'  {DIM}[Ahmia] could not locate hidden token in homepage form{RESET}')
    except Exception as e:
        if debug:
            print(f'  {DIM}[Ahmia] token fetch error: {e}{RESET}')
    return None

def fetch_torch_search_token(session: requests.Session, base_url: str, debug: bool) -> dict[str, str] | None:
    '''
    Torch embeds a tkn and several hidden fields in its homepage form.
    Returns a dict of all required params, or None on failure.
    '''
    try:
        resp = tor_get(session, base_url + '/cgi-bin/omega/omega')
        soup = BeautifulSoup(resp.text, 'html.parser')
        fields: dict[str, str] = {}
        for name in ('DB', 'FMT', 'xDB', 'xFILTERS', 'tkn'):
            el = soup.find('input', {'name': name})
            if el:
                fields[name] = str(el.get('value', '')).strip()
        if 'tkn' not in fields:
            if debug:
                print(f'  {DIM}[Torch] could not locate tkn in homepage form{RESET}')
            return None
        return fields
    except Exception as e:
        if debug:
            print(f'  {DIM}[Torch] token fetch error: {e}{RESET}')
        return None
    
def scrape_torch(
    session: requests.Session,
    cfg: IndexConfig,
    query: str,
    pages: int,
    debug: bool,
) -> tuple[list[RawResult], list[str]]:
    '''Torch-specific scraper — handles token + xP pagination.'''
    all_results: list[RawResult] = []
    errors: list[str] = []

    print(f'{DIM}  Checking reachability...{RESET}', end=' ', flush=True)
    if not check_onion_reachable(session, cfg.base_url, debug):
        print(f'{R}unreachable.{RESET}')
        return [], ['Torch — .onion address unreachable']
    print(f'{G}ok.{RESET}')

    fields = fetch_torch_search_token(session, cfg.base_url, debug)
    if not fields:
        return [], ['Torch — could not fetch search token from homepage']

    xp_value: str | None = None

    for page in range(1, pages + 1):
        params: dict[str, str] = {
            'P': query,
            'DEFAULTOP': 'and',
            'DB': fields.get('DB', 'default'),
            'FMT': fields.get('FMT', 'query'),
            'xDB': fields.get('xDB', 'default'),
            'xFILTERS': fields.get('xFILTERS', '.~~'),
            'tkn': fields.get('tkn', ''),
        }
        if page > 1:
            params['['] = str(page)
            if xp_value:
                params['xP'] = xp_value

        url = cfg.base_url + cfg.search_path + '?' + '&'.join(
            f'{k}={quote_plus(v)}' for k, v in params.items()
        )

        if debug:
            print(f'  {DIM}[Torch] page {page} URL: {url}{RESET}')

        try:
            resp = tor_get(session, url)
            resp.raise_for_status()
        except requests.exceptions.Timeout:
            errors.append(f'Torch timed out on page {page}')
            break
        except requests.exceptions.ConnectionError as e:
            errors.append(f'Torch connection error on page {page}: {e}')
            break
        except requests.exceptions.HTTPError:
            errors.append(f'Torch HTTP error on page {page}')
            break
        except Exception as e:
            errors.append(f'Torch unexpected error on page {page}: {e}')
            break

        try:
            soup = BeautifulSoup(resp.text, 'html.parser')
            if debug:
                print(f'  {DIM}[Torch] page {page} HTML preview:\n{resp.text[:3000]}{RESET}')
        except Exception as e:
            errors.append(f'Torch HTML parse error on page {page}: {e}')
            break

        # Extract xP from results page for subsequent pagination
        xp_el = soup.find('input', {'name': 'xP'})
        if xp_el:
            xp_value = str(xp_el.get('value', '')).strip()  # type: ignore[union-attr]

        containers = soup.select(cfg.result_selector)
        if debug and not containers:
            print(f'  {DIM}[Torch] page {page}: selector "{cfg.result_selector}" matched 0 elements{RESET}')

        for container in containers:
            a_el = container.select_one('b a')
            if not a_el:
                continue
            title = a_el.get_text(strip=True)
            href = str(a_el.get('href', '')).strip()
            snippet = ''
            snip_el = container.select_one('small')
            if snip_el:
                snippet = snip_el.get_text(strip=True)
            if not href or not extract_onion_host(href):
                continue
            all_results.append(RawResult(
                title=title or '(no title)',
                url=href,
                snippet=snippet[:300],
                source_index=cfg.name,
                page=page,
            ))

        if page < pages:
            time.sleep(INTER_PAGE_DELAY)

    return all_results, errors

# Per-index scrapers
def _build_search_url(cfg: IndexConfig, query: str, page: int, extra_param: tuple[str, str] | None = None) -> str:
    encoded = quote_plus(query)
    page_offset = (page - 1) * 20
    path = (
        cfg.search_path
        .replace('{query}', encoded)
        .replace('{page_offset}', str(page_offset))
    )
    url = cfg.base_url + path
    if page > 1:
        if cfg.name == 'Tor66':
            url += f'&sorttype=rel&page={page}'
        else:
            url += f'&page={page}' # Check this !!
    if extra_param:
        url += f'&{extra_param[0]}={extra_param[1]}'
    return url

def _scrape_page(
    session: requests.Session,
    cfg: IndexConfig,
    query: str,
    page: int,
    debug: bool,
    extra_param: tuple[str, str] | None = None,
) -> tuple[list[RawResult], str | None]:
    '''
    Scrape one page from one index.
    Returns (results, error_message). error_message is None on success.
    '''
    url = _build_search_url(cfg, query, page, extra_param)
    try:
        if cfg.name == 'Amnesia' and page > 1:
            post_data: dict[str, str] = {'page': str(page)}
            resp = tor_post(session, url, post_data)
        else:
            resp = tor_get(session, url)
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        return [], f'{cfg.name} timed out on page {page} (circuit may be slow)'
    except requests.exceptions.ConnectionError as e:
        return [], f'{cfg.name} connection error on page {page}: {e}'
    except requests.exceptions.HTTPError:
        return [], f'{cfg.name} HTTP error on page {page}'
        # return [], f'{cfg.name} HTTP {resp.status_code} on page {page}'
    except Exception as e:
        return [], f'{cfg.name} unexpected error on page {page}: {e}'

    try:
        soup = BeautifulSoup(resp.text, 'html.parser')
        if debug:
            print(f'  {DIM}[{cfg.name}] page {page} URL: {url}{RESET}')
            print(f'  {DIM}[{cfg.name}] page {page} HTML preview:\n{resp.text[:3000]}{RESET}')
    except Exception as e:
        return [], f'{cfg.name} HTML parse error on page {page}: {e}'

    raw: list[RawResult] = []
    containers = soup.select(cfg.result_selector)

    if debug and not containers:
        print(f'  {DIM}[{cfg.name}] page {page}: selector "{cfg.result_selector}" matched 0 elements{RESET}')

    for container in containers: 
        if cfg.name == 'Tor66': # Tor66: <b><a href='...'>Title</a></b> <br>Snippet (flat, no wrapper div)
            a_el = container.select_one('a')
            if not a_el:
                continue
            title = a_el.get_text(strip=True)
            href = str(a_el.get('href', '')).strip()
            # Snippet is the text node immediately following the <br> after this <b>
            snippet = ''
            br = container.find_next_sibling('br')
            if br is not None:
                next_node = br.next_sibling
                if next_node and hasattr(next_node, 'strip'):
                    snippet = str(next_node).strip()
            if not href or not extract_onion_host(href):
                continue
            raw.append(RawResult(
                title=title or '(no title)',
                url=href,
                snippet=snippet[:300],
                source_index=cfg.name,
                page=page,
            ))
            continue
        
        if cfg.name == 'Amnesia': # Amnesia: <div class="results"><h2><a href="...">Title</a></h2>...<p class="site_desc">Snippet</p></div>
            a_el = container.select_one('h2 a')
            if not a_el:
                continue
            title = a_el.get_text(strip=True)
            href = str(a_el.get('href', '')).strip()
            snippet = ''
            snip_el = container.select_one('p.site_desc')
            if snip_el:
                snippet = snip_el.get_text(strip=True)
            if not href or not extract_onion_host(href):
                continue
            raw.append(RawResult(
                title=title or '(no title)',
                url=href,
                snippet=snippet[:300],
                source_index=cfg.name,
                page=page,
            ))
            continue

        # Title
        title_el = container.select_one(cfg.title_selector) if cfg.title_selector else None
        title = title_el.get_text(strip=True) if title_el else ''

        # URL — try the selector, fall back to nearest <a>
        if cfg.url_selector == 'cite':
            url_el = container.select_one('cite')
            href = url_el.get_text(strip=True) if url_el else ''
            if not href: # Ahmia puts the real URL in the <a> inside the result
                a = container.select_one('a')
                href = a.get('href', '') if a else ''
        elif cfg.name == 'notevil':
            href = container.get('href', '') # container itself is the <a>
        else:
            url_el = container.select_one(cfg.url_selector)
            href = url_el.get('href', '') if url_el else ''

        href = str(href).strip()

        # Snippet
        snippet = ''
        if cfg.snippet_selector:
            snip_el = container.select_one(cfg.snippet_selector)
            if snip_el:
                snippet = snip_el.get_text(strip=True)

        # Only keep results with a parseable .onion URL
        if not href or not extract_onion_host(href):
            continue

        raw.append(RawResult(
            title=title or '(no title)',
            url=href,
            snippet=snippet[:300],
            source_index=cfg.name,
            page=page,
        ))

    return raw, None

def scrape_index(
    session: requests.Session,
    cfg: IndexConfig,
    query: str,
    pages: int,
    debug: bool,
) -> tuple[list[RawResult], list[str]]:
    '''
    Scrape `pages` pages from one index.
    Returns (all_raw_results, list_of_error_messages).
    '''
    all_results: list[RawResult] = []
    errors: list[str] = []
    extra_param: tuple[str, str] | None = None

    if cfg.name == 'Torch': # Needs special care
        return scrape_torch(session, cfg, query, pages, debug)
    
    if cfg.name != 'Ahmia': # This assumes Ahmia is reachable (might not be)
        print(f'{DIM}  Checking reachability...{RESET}', end=' ', flush=True)
        if not check_onion_reachable(session, cfg.base_url, debug):
            print(f'{R}unreachable.{RESET}')
            return [], [f'{cfg.name} — .onion address unreachable (service may be down or address outdated)']
        print(f'{G}ok.{RESET}')
    if cfg.name == 'Ahmia':
        extra_param = fetch_ahmia_search_token(session, cfg.base_url, debug)
        if debug:
            print(f'  {DIM}[Ahmia] token result: {extra_param}{RESET}')
        if not extra_param:
            return [], ['Ahmia — could not fetch search token from homepage']
    effective_pages = 1 if not cfg.paginated else pages
    for page in range(1, effective_pages + 1):
        results, err = _scrape_page(session, cfg, query, page, debug, extra_param=extra_param)
        if err:
            errors.append(err)
            if debug:
                print(f'  {Y}[WARN] {err}{RESET}')
        all_results.extend(results)
        if page < pages:
            time.sleep(INTER_PAGE_DELAY)

    return all_results, errors

# Aggregation & deduplication
def aggregate_and_dedup(raw: list[RawResult]) -> list[BranchedResult]:
    '''
    Group results by canonical .onion host. Within each host group,
    collect distinct paths as branches. Link farm hosts are flagged
    but not discarded.

    Ordering: hosts with more unique source indexes first, then by
    number of distinct paths (more = more mentions = more relevant).
    '''
    # host -> {paths, titles, snippets, source_indexes}
    host_map: dict[str, dict[str, Any]] = {}

    for r in raw:
        host = extract_onion_host(r.url)
        if not host:
            continue
        path = canonical_url_path(r.url)

        if host not in host_map:
            host_map[host] = {
                'paths': [],
                'path_set': set(),
                'title': r.title,
                'snippet': r.snippet,
                'source_indexes': [],
                'source_set': set(),
            }

        entry = host_map[host]

        # Add path if not seen before for this host
        if path not in entry['path_set']:
            entry['paths'].append(path)
            entry['path_set'].add(path)

        # Track title/snippet from first result that has them
        if entry['title'] == '(no title)' and r.title != '(no title)':
            entry['title'] = r.title
        if not entry['snippet'] and r.snippet:
            entry['snippet'] = r.snippet

        # Track which indexes mentioned this host
        if r.source_index not in entry['source_set']:
            entry['source_indexes'].append(r.source_index)
            entry['source_set'].add(r.source_index)

    branched: list[BranchedResult] = []
    for host, data in host_map.items():
        branched.append(BranchedResult(
            canonical_host=host,
            paths=data['paths'],
            title=data['title'],
            snippet=data['snippet'],
            source_indexes=data['source_indexes'],
            is_link_farm=is_link_farm(host),
        ))

    # Sort: most cross-index mentions first, then most paths
    branched.sort(key=lambda b: (len(b.source_indexes), len(b.paths)), reverse=True)
    return branched

# Display
def _source_tag(indexes: list[str]) -> str:
    abbrevs = {'Ahmia': 'AH', 'Torch': 'TC', 'Tor66': 'T6', 'notevil': 'NE', 'Amnesia': 'AM'}
    return ' '.join(abbrevs.get(i, i[:2].upper()) for i in indexes)

def display_results_rich(run: SearchRun) -> None:
    assert Console is not None and Table is not None and box is not None and Text is not None and Panel is not None
    console = Console() # Ugly
    results = run.results
    shown = results[:CLI_RESULT_LIMIT]
    remainder = len(results) - len(shown)

    console.print()
    console.print(
        Panel(
            f'[bold cyan]Query:[/] {run.query}\n'
            f'[bold cyan]Run time:[/] {run.run_time}\n'
            f'[bold cyan]Pages per index:[/] {run.pages_per_index}\n'
            f'[bold cyan]Raw results:[/] {run.total_raw}   '
            f'[bold cyan]After dedup:[/] {run.total_after_dedup}\n'
            f'[bold cyan]Indexes:[/] {", ".join(run.indexes_queried)}\n'
            + (f'[bold red]Failed:[/] {", ".join(run.indexes_failed)}' if run.indexes_failed else ''),
            title='[bold]Search Summary[/]',
            border_style='blue',
        )
    )

    if not shown:
        console.print(f'\n[yellow]No results found.[/]\n')
        return

    table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style='bold blue',
        expand=True,
        padding=(0, 1),
        show_lines=True
    )
    table.add_column('#', style='dim', width=4, no_wrap=True)
    table.add_column('Title', style='bold white', min_width=20)
    table.add_column('Canonical Host', style='cyan', min_width=20, overflow='fold')
    table.add_column('Paths', style='dim', min_width=10)
    table.add_column('Src', style='green', width=10, no_wrap=True)
    table.add_column('Snippet', style='dim white', min_width=20)

    for i, result in enumerate(shown, 1):
        host_display = Text(result.canonical_host)
        if result.is_link_farm:
            host_display = Text(result.canonical_host + ' ⚑', style='red')

        # Format paths as a readable branched list
        if len(result.paths) == 1:
            paths_display = result.paths[0]
        else:
            paths_display = '\n'.join(f'├ {p}' if j < len(result.paths) - 1 else f'└ {p}'
                                      for j, p in enumerate(result.paths))

        snippet = (result.snippet[:120] + '…') if len(result.snippet) > 120 else result.snippet
        title = (result.title[:60] + '…') if len(result.title) > 60 else result.title

        table.add_row(
            str(i),
            title,
            host_display,
            paths_display,
            _source_tag(result.source_indexes),
            snippet or '—',
        )

    console.print(table)

    if remainder > 0:
        console.print(
            f'[dim]  … {remainder} more result(s) not shown. See JSON output for full list.[/]\n'
        )
    if run.indexes_failed:
        console.print(f'[yellow]  Indexes with errors: {", ".join(run.indexes_failed)}[/]\n')

def display_results_plain(run: SearchRun) -> None:
    '''Fallback display when rich is not installed.'''
    print('''
                                    O̢̩̩͉̦̘҉̶̵̷̧̨̛̞̗͔̼͍̼͎͈̦̝͙̰̜̤͕̼̱͕̣͇̱̯͓̭̲̰̹̬̳̉̉̎ͭͧ́͘͘̕͟͢͠͠͞͠͞ͅ҉ ̡̢̲̙̼͖̘̩̠̮̹͎̏͐̅̆̂́͢҉̳͖̬͚̯O̦̺͙̲ͅ
          
''')
    print(f'\n{DIVIDER}')
    print(f'  Query        : {run.query}')
    print(f'  Run time     : {run.run_time}')
    print(f'  Raw results  : {run.total_raw}')
    print(f'  After dedup  : {run.total_after_dedup}')
    if run.indexes_failed:
        print(f'  Failed       : {", ".join(run.indexes_failed)}')
    print(DIVIDER)

    shown = run.results[:CLI_RESULT_LIMIT]
    for i, r in enumerate(shown, 1):
        farm_flag = ' [LINK FARM]' if r.is_link_farm else ''
        print(f'\n{B}{BOLD}[{i}]{RESET} {W}{r.title}{RESET}{farm_flag}')
        print(f'  {C}{r.canonical_host}{RESET}')
        src = _source_tag(r.source_indexes)
        print(f'  {DIM}Sources: {src}{RESET}')
        for j, p in enumerate(r.paths):
            prefix = '├' if j < len(r.paths) - 1 else '└'
            print(f'  {DIM}{prefix} {p}{RESET}')
        if r.snippet:
            snip = r.snippet[:120] + ('…' if len(r.snippet) > 120 else '')
            print(f'  {DIM}{snip}{RESET}')

    remainder = len(run.results) - len(shown)
    if remainder > 0:
        print(f'\n{DIM}  … {remainder} more result(s) not shown. Full list saved to JSON.{RESET}')
    print(f'\n{DIVIDER}\n')

# JSON output
def save_results(run: SearchRun) -> str:
    safe_query = re.sub(r'[^\w.-]', '_', run.query)[:40]
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'Erebus_{safe_query}_{timestamp}.json'

    data: dict[str, Any] = {
        'query': run.query,
        'run_time': run.run_time,
        'pages_per_index': run.pages_per_index,
        'total_raw': run.total_raw,
        'total_after_dedup': run.total_after_dedup,
        'indexes_queried': run.indexes_queried,
        'indexes_failed': run.indexes_failed,
        'results': [
            {
                'canonical_host': r.canonical_host,
                'title': r.title,
                'snippet': r.snippet,
                'paths': r.paths,
                'source_indexes': r.source_indexes,
                'is_link_farm': r.is_link_farm,
                'full_urls': [f'http://{r.canonical_host}{p}' for p in r.paths],
            }
            for r in run.results
        ],
    }

    with open(filename, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)

    return filename

def save_results_html(run: SearchRun) -> str:
    assert Console is not None and Table is not None and box is not None and Text is not None
    safe_query = re.sub(r'[^\w.-]', '_', run.query)[:40]
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'Erebus_{safe_query}_{timestamp}.html'

    console = Console(record=True, width=160)

    console.print()
    console.print(f'[bold cyan]Query:[/]          {run.query}')
    console.print(f'[bold cyan]Run time:[/]       {run.run_time}')
    console.print(f'[bold cyan]Pages per index:[/] {run.pages_per_index}')
    console.print(f'[bold cyan]Raw results:[/]    {run.total_raw}   '
                  f'[bold cyan]After dedup:[/] {run.total_after_dedup}')
    console.print(f'[bold cyan]Indexes:[/]        {", ".join(run.indexes_queried)}')
    if run.indexes_failed:
        console.print(f'[bold red]Failed:[/]         {", ".join(run.indexes_failed)}')
    console.print()

    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style='bold blue',
        expand=True,
        padding=(0, 1),
        show_lines=True,
    )
    table.add_column('#', style='dim', width=4, no_wrap=True)
    table.add_column('Title', style='bold white', min_width=20)
    table.add_column('Canonical Host', style='cyan', min_width=20, overflow='fold')
    table.add_column('Paths', style='dim', min_width=10)
    table.add_column('Src', style='green', width=10, no_wrap=True)
    table.add_column('Snippet', style='dim white', min_width=20)

    for i, result in enumerate(run.results, 1): # Full set, no CLI_RESULT_LIMIT
        host_display = Text(result.canonical_host)
        if result.is_link_farm:
            host_display = Text(result.canonical_host + ' ⚑', style='red')

        if len(result.paths) == 1:
            paths_display = result.paths[0]
        else:
            paths_display = '\n'.join(
                f'├ {p}' if j < len(result.paths) - 1 else f'└ {p}'
                for j, p in enumerate(result.paths)
            )

        snippet = (result.snippet[:180] + '…') if len(result.snippet) > 180 else result.snippet
        title = (result.title[:80] + '…') if len(result.title) > 80 else result.title

        table.add_row(
            str(i),
            title,
            host_display,
            paths_display,
            _source_tag(result.source_indexes),
            snippet or '—',
        )

    console.print(table)
    console.save_html(filename)
    return filename

# Argument parsing
def parse_args() -> tuple[int, bool, bool, bool]:
    '''Returns (pages, debug, save_json, save_html).'''
    pages = DEFAULT_PAGES
    debug = '--debug' in sys.argv
    no_save = '--no-save' in sys.argv
    explicit_j = '--save-j' in sys.argv
    explicit_h = '--save-h' in sys.argv
    neither = not explicit_j and not explicit_h
    save_json = not no_save and (explicit_j or neither)
    save_html = not no_save and (explicit_h or neither)

    if '--pages' in sys.argv:
        idx = sys.argv.index('--pages')
        try:
            pages = int(sys.argv[idx + 1])
            if not 1 <= pages <= MAX_PAGES:
                print(f'{Y}[WARN] --pages must be 1-{MAX_PAGES}. Clamping.{RESET}')
                pages = max(1, min(MAX_PAGES, pages))
        except (IndexError, ValueError):
            print(f'{Y}[WARN] --pages requires an integer argument. Using default ({DEFAULT_PAGES}).{RESET}')

    return pages, debug, save_json, save_html

# Entry point
def main() -> int:
    pages, debug, save_json, save_html = parse_args()

    print(BANNER)
    print('All requests routed through Tor.')
    print('For authorized research and investigative use only.\n')
    print(DIVIDER)
    print()

    if not STEM_AVAILABLE:
        print(f'{R}[ERROR] stem is required. Install with: pip install stem{RESET}\n')
        return 1

    if not RICH_AVAILABLE:
        print(f'{Y}[WARN] rich not installed — falling back to plain output.{RESET}')
        print(f'{Y}       Install with: pip install rich{RESET}\n')

    # Query input
    print(f'{Y}Enter search term:{RESET}')
    query = input(f'{C}> Search: {RESET}').strip()
    if not query:
        sys.exit(f'\n{R}[ERROR] No search term provided.{RESET}\n')

    # Page count confirmation if > 1
    if pages > 1:
        print(f'\n{Y}[NOTE] Fetching {pages} pages per index across {len(INDEXES)} indexes.')
        print(f'       This may take several minutes due to Tor latency.{RESET}\n')

    # Tor setup
    print(f'\n{DIM}Initializing Tor...{RESET}')
    tor_process, tor_status = launch_tor_process(debug=debug)
    print(f'  {G}Tor ready.{RESET} (version: {tor_status.tor_version})\n')

    session = build_tor_session()

    # Run searches
    all_raw: list[RawResult] = []
    failed_indexes: list[str] = []
    queried_indexes: list[str] = []

    try:
        for idx_num, cfg in enumerate(INDEXES):
            # Rotate circuit between indexes
            if idx_num > 0 and tor_status.control_available:
                print(f'{DIM}Rotating circuit...{RESET}', end=' ', flush=True)
                ok = rotate_circuit(debug=debug)
                print(f'{G}done.{RESET}' if ok else f'{Y}skipped (control unavailable).{RESET}')

            print(f'{B}[{cfg.name}]{RESET} Querying ({pages} page(s))...', end=' ', flush=True)
            results, errors = scrape_index(session, cfg, query, pages, debug)

            if errors and not results:
                print(f'{R}failed.{RESET}')
                for e in errors:
                    print(f'  {R}[ERROR] {e}{RESET}')
                failed_indexes.append(cfg.name)
            else:
                print(f'{G}{len(results)} result(s).{RESET}')
                if errors and debug:
                    for e in errors:
                        print(f'  {Y}[WARN] {e}{RESET}')
                queried_indexes.append(cfg.name)
                all_raw.extend(results)

    finally:
        if tor_process is not None:
            print(f'\n{DIM}Shutting down managed Tor process...{RESET}')
            try:
                tor_process.kill() # type: ignore[union-attr]
                print(f'  {G}Tor process shut down cleanly.{RESET}')
            except Exception as e:
                print(f'  {Y}Warning: could not shut down Tor: {e}{RESET}')

    # Deduplication and aggregation
    branched = aggregate_and_dedup(all_raw)

    run = SearchRun(
        query=query,
        run_time=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        pages_per_index=pages,
        total_raw=len(all_raw),
        total_after_dedup=len(branched),
        indexes_queried=queried_indexes,
        indexes_failed=failed_indexes,
        results=branched,
    )

    # Display
    if RICH_AVAILABLE:
        display_results_rich(run)
    else:
        display_results_plain(run)

    # Save JSON
    if save_json:
        do_json = '--save-j' in sys.argv or input(f'{C}> Save results to JSON? [Y/n]: {RESET}').strip().lower() != 'n'
        if do_json:
            filename = save_results(run)
            if RICH_AVAILABLE and Console is not None:
                Console().print(f'[green]  Results saved → {filename}[/]\n')
            else:
                print(f'{G}  Results saved → {filename}{RESET}\n')

    # Save HTML
    if save_html and RICH_AVAILABLE:
        do_html = '--save-h' in sys.argv or input(f'{C}> Save full results to HTML? [Y/n]: {RESET}').strip().lower() != 'n'
        if do_html:
            filename = save_results_html(run)
            Console().print(f'[green]  HTML saved → {filename}[/]\n') # type: ignore
    elif save_html and not RICH_AVAILABLE:
        print(f'{Y}[WARN] rich is required for HTML export. Install with: pip install rich{RESET}\n')

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f'\n\n{DIM}[Aborted]{RESET}')
        sys.exit(130)