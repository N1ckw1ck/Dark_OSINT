#!/usr/bin/env python3

'''
pipeline.py — Automation!

Runs the full dark web OSINT pipeline for one or more search terms,
chaining each tool and passing output files between them automatically.

Usage:
  python pipeline.py <query> [query2 ...] [options]

  python pipeline.py "ransomware"
  python pipeline.py "ransomware" "leaked credentials" --pages 3
  python pipeline.py "malware" --pages 5 --no-khaeos
  python pipeline.py "forums" --khaeos-db /path/to/khaeos.db

Options:
  --pages N       Pages per Erebus index (default: 1)
  --no-mnemosyne  Skip Mnemosyne scan (Erebus + Hemera only)
  --no-khaeos     Skip Khaeos ingest
  --khaeos-db     Path to khaeos.db (default: auto-detect khaeos.db next to this script)
  --include-farms Pass --include-farms to Hemera
  --full-paths    Pass --full-paths to Hemera
  --aggressive    Pass --aggressive to Mnemosyne (queues discovered .onion
                   links from each scanned page into output/discovery_queue.txt
                   for a future run — nothing extra is scanned this run)
  --dry-run       Print commands without running them

For authorized research and investigative use only.
'''

from __future__ import annotations

import re
import sys
import time
import subprocess
import glob
import os
from datetime import datetime
from pathlib import Path

# ANSI
R = '\033[91m'
G = '\033[92m'
Y = '\033[93m'
C = '\033[96m'
DIM = '\033[2m'
BOLD = '\033[1m'
RST = '\033[0m'

BANNER = f'''{C}
██████╗ ██╗██████╗ ███████╗██╗     ██╗███╗   ██╗███████╗
██╔══██╗██║██╔══██╗██╔════╝██║     ██║████╗  ██║██╔════╝
██████╔╝██║██████╔╝█████╗  ██║     ██║██╔██╗ ██║█████╗
██╔═══╝ ██║██╔═══╝ ██╔══╝  ██║     ██║██║╚██╗██║██╔══╝
██║     ██║██║     ███████╗███████╗██║██║ ╚████║███████╗
╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝
{RST}
{DIM}Erebus → Hemera → Mnemosyne → Khaeos{RST}
'''

DIVIDER = '─' * 62

HERE = Path(__file__).resolve().parent
OUTPUT_DIR = HERE / 'output'
EREBUS_DIR = OUTPUT_DIR / 'erebus'
HEMERA_DIR = OUTPUT_DIR / 'hemera'
MNEMOSYNE_DIR = OUTPUT_DIR / 'mnemosyne'

# In this repo, d_erebus.py / d_hemera.py / d_mnemosyne.py live at the repo root and d_khaeos.py lives under Khaeos/, 
# while this script lives under Pipeline/VPS_Files/ — three levels down. On a deployed VPS, the standard deploy step 
# copies all of them flat into one directory alongside this script instead (see the "Deploy Tools to VPS" docs). 
# pipeline.py checks next to this script first, then falls back to the repo layout so `python pipeline.py ...` also works straight out of a clone.
REPO_ROOT = HERE.parent.parent


def resolve_script(name: str, *extra_candidates: Path) -> Path:
    '''Find a sibling tool script, whether flat-deployed or run from a clone.'''
    for candidate in (HERE / name, *extra_candidates, REPO_ROOT / name):
        if candidate.exists():
            return candidate
    return HERE / name # not found anywhere — keep the clearest path for the error


EREBUS_SCRIPT = resolve_script('d_erebus.py')
HEMERA_SCRIPT = resolve_script('d_hemera.py')
MNEMOSYNE_SCRIPT = resolve_script('d_mnemosyne.py')
KHAEOS_SCRIPT = resolve_script('d_khaeos.py', REPO_ROOT / 'Khaeos' / 'd_khaeos.py')


# Helpers
def log(msg: str, color: str = '') -> None:
    ts = datetime.now().strftime('%H:%M:%S')
    print(f'{DIM}[{ts}]{RST} {color}{msg}{RST}')


def log_step(n: int, total: int, label: str) -> None:
    print(f'\n{DIVIDER}')
    print(f'{C}{BOLD}  STEP {n}/{total} — {label}{RST}')
    print(f'{DIVIDER}')


def run(cmd: list[str], *, dry_run: bool = False, cwd: Path | None = None) -> int:
    '''Run a command, stream output live, return exit code.'''
    display = ' '.join(str(c) for c in cmd)
    log(f'$ {display}', DIM)
    if dry_run:
        return 0
    result = subprocess.run(cmd, cwd=str(cwd) if cwd else None)
    return result.returncode


def find_latest(pattern: str) -> Path | None:
    '''Return the most recently modified file matching a glob pattern.'''
    matches = glob.glob(pattern)
    if not matches:
        return None
    return Path(max(matches, key=os.path.getmtime))


def safe_name(query: str) -> str:
    return re.sub(r'[^\w.-]', '_', query)[:40]


# Arg parsing
def parse_args() -> tuple[list[str], dict[str, object]]:
    args = sys.argv[1:]

    if not args or args[0] in ('-h', '--help'):
        print(__doc__)
        sys.exit(0)

    queries: list[str] = []
    opts: dict[str, object] = {
        'pages': 1,
        'no_mnemosyne': False,
        'no_khaeos': False,
        'khaeos_db': None,
        'include_farms': False,
        'full_paths': False,
        'dry_run': False,
        'aggressive': False,
    }

    i = 0
    while i < len(args):
        a = args[i]
        if a == '--pages':
            i += 1
            try:
                opts['pages'] = int(args[i])
            except (IndexError, ValueError):
                sys.exit(f'{R}[ERROR] --pages requires an integer.{RST}')
        elif a == '--no-mnemosyne':
            opts['no_mnemosyne'] = True
        elif a == '--no-khaeos':
            opts['no_khaeos'] = True
        elif a == '--include-farms':
            opts['include_farms'] = True
        elif a == '--full-paths':
            opts['full_paths'] = True
        elif a == '--dry-run':
            opts['dry_run'] = True
        elif a == '--aggressive':
            opts['aggressive'] = True
        elif a == '--khaeos-db':
            i += 1
            try:
                opts['khaeos_db'] = args[i]
            except IndexError:
                sys.exit(f'{R}[ERROR] --khaeos-db requires a path.{RST}')
        elif not a.startswith('--'):
            queries.append(a)
        i += 1

    if not queries:
        sys.exit(f'\n{R}[ERROR] No search query provided.{RST}\n'
                 f'Usage: python pipeline.py "your query" [options]\n')

    return queries, opts


# Pipeline
def run_pipeline(query: str, opts: dict[str, object], query_n: int, total_queries: int) -> bool:
    '''
    Run the full pipeline for a single query.
    Returns True if completed without fatal errors.
    '''
    pages = int(str(opts['pages']))
    no_mnem = bool(opts['no_mnemosyne'])
    no_khaeos = bool(opts['no_khaeos'])
    inc_farms = bool(opts['include_farms'])
    full_paths = bool(opts['full_paths'])
    dry_run = bool(opts['dry_run'])
    aggressive = bool(opts['aggressive'])
    khaeos_db = opts['khaeos_db']

    total_steps = 2 + (0 if no_mnem else 1) + (0 if no_khaeos else 1)

    print(f'\n{BOLD}{C}{"═" * 62}{RST}')
    print(f'{BOLD}{C}  Query {query_n}/{total_queries}: {query!r}{RST}')
    print(f'{BOLD}{C}{"═" * 62}{RST}')

    # First Erebus — output kept in its own subfolder, not loose next to the scripts
    log_step(1, total_steps, 'Erebus — dark web search')

    EREBUS_DIR.mkdir(parents=True, exist_ok=True)

    erebus_cmd = [
        sys.executable, str(EREBUS_SCRIPT),
        '--pages', str(pages),
        '--save-j'
    ]
    # Erebus uses input() so pipe it
    log(f'Running Erebus (pages={pages})…', C)
    if dry_run:
        log(f'[dry-run] would run erebus with query: {query!r}', DIM)
        erebus_json = EREBUS_DIR / f'Erebus_{safe_name(query)}_DRYRUN.json'
    else:
        proc = subprocess.run(
            erebus_cmd,
            input=query + '\n',
            text=True,
            cwd=str(EREBUS_DIR),
        )
        if proc.returncode not in (0, None):
            log(f'Erebus exited with code {proc.returncode} — aborting this query.', R)
            return False

        # Find the JSON Erebus just wrote (most recent Erebus_*.json)
        erebus_json = find_latest(str(EREBUS_DIR / 'Erebus_*.json'))
        if not erebus_json:
            log('Could not find Erebus JSON output — aborting.', R)
            return False
        log(f'Erebus output: {erebus_json.name}', G)

    # Hemera — output kept in its own subfolder too
    log_step(2, total_steps, 'Hemera — URL extraction')

    HEMERA_DIR.mkdir(parents=True, exist_ok=True)

    hemera_cmd = [
        sys.executable, str(HEMERA_SCRIPT),
        str(erebus_json),
    ]
    if inc_farms:
        hemera_cmd.append('--include-farms')
    if full_paths:
        hemera_cmd.append('--full-paths')

    rc = run(hemera_cmd, dry_run=dry_run, cwd=HEMERA_DIR)
    if rc not in (0, None):
        log(f'Hemera exited with code {rc} — aborting.', R)
        return False

    if dry_run:
        hemera_txt = HEMERA_DIR / f'erebus_urls_{safe_name(query)}_DRYRUN.txt'
    else:
        hemera_txt = find_latest(str(HEMERA_DIR / 'erebus_urls_*.txt'))
        if not hemera_txt:
            log('Could not find Hemera .txt output — aborting.', R)
            return False
        log(f'Hemera output: {hemera_txt.name}', G)

    if no_mnem:
        log('--no-mnemosyne set — skipping scan and Khaeos ingest.', Y)
        return True

    # Mnemosyne
    log_step(3, total_steps, 'Mnemosyne — .onion recon')

    mnem_cmd = [
        sys.executable, str(MNEMOSYNE_SCRIPT),
        '--batch', str(hemera_txt),
        '--save',
    ]
    if aggressive:
        mnem_cmd += ['--aggressive', '--discovery-out', str(OUTPUT_DIR / 'discovery_queue.txt')]

    MNEMOSYNE_DIR.mkdir(parents=True, exist_ok=True)
    display = ' '.join(str(c) for c in mnem_cmd)
    log(f'$ {display}', DIM)
    if not dry_run:
        rc = subprocess.run(mnem_cmd, cwd=str(MNEMOSYNE_DIR)).returncode
        if rc not in (0, None):
            log(f'Mnemosyne exited with code {rc}.', Y)
            # Non-fatal — partial results may still have been written

    if dry_run:
        mnem_json = MNEMOSYNE_DIR / f'Mnemosyne_batch_DRYRUN.json'
    else:
        mnem_json = find_latest(str(MNEMOSYNE_DIR / 'Mnemosyne_batch_*.json'))
        if not mnem_json:
            log('Could not find Mnemosyne batch JSON — skipping Khaeos ingest.', Y)
            return True
        log(f'Mnemosyne output: {mnem_json.name}', G)

    if no_khaeos:
        log('--no-khaeos set — skipping ingest.', Y)
        return True

    # Optional Khaeos ingest
    log_step(4, total_steps, 'Khaeos — ingest')

    khaeos_cmd = [
        sys.executable, str(KHAEOS_SCRIPT),
        '--ingest', str(mnem_json),
    ]
    if khaeos_db:
        khaeos_cmd += ['--db', str(khaeos_db)]

    rc = run(khaeos_cmd, dry_run=dry_run)
    if rc not in (0, None):
        log(f'Khaeos ingest exited with code {rc}.', Y)

    log('Pipeline complete for this query.', G)
    return True


# Main
def main() -> int:
    queries, opts = parse_args()

    print(BANNER)

    dry_run = bool(opts['dry_run'])
    if dry_run:
        print(f'{Y}{BOLD}  DRY RUN — no commands will be executed{RST}\n')

    print(f'  {DIM}Queries   :{RST} {len(queries)}')
    print(f'  {DIM}Pages/idx :{RST} {opts["pages"]}')
    print(f'  {DIM}Mnemosyne :{RST} {"skip" if opts["no_mnemosyne"] else "yes"}')
    print(f'  {DIM}Khaeos    :{RST} {"skip" if opts["no_khaeos"] else "yes"}')
    print(f'  {DIM}Tool dir  :{RST} {HERE}')
    print()

    results: list[tuple[str, bool]] = []
    start = time.time()

    for i, query in enumerate(queries, 1):
        ok = run_pipeline(query, opts, i, len(queries))
        results.append((query, ok))
        if len(queries) > 1 and i < len(queries):
            log(f'Waiting 10s before next query…', DIM)
            if not dry_run:
                time.sleep(10)

    # Summary
    elapsed = time.time() - start
    print(f'\n{DIVIDER}')
    print(f'{BOLD}  Pipeline summary — {elapsed:.0f}s elapsed{RST}')
    print(DIVIDER)
    for query, ok in results:
        status = f'{G}✓ ok{RST}' if ok else f'{R}✗ error{RST}'
        print(f'  {status}  {DIM}{query!r}{RST}')
    print()

    failed = sum(1 for _, ok in results if not ok)
    return 1 if failed else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f'\n\n{DIM}[Pipeline interrupted]{RST}')
        sys.exit(130)