#!/usr/bin/env python3

'''
Erebus URL Extractor

Parses a JSON file produced by d_erebus.py and extracts all .onion URLs
for use as input to d_mnemosyne.py --batch.

Deduplication:
  • Only canonical root URLs (http://<host>/) are written by default.
    Use --full-paths to emit every unique path seen per host instead.
  • Link-farm-flagged hosts are excluded by default.
    Use --include-farms to include them (a warning is shown).

Output:
  • One URL per line written to <output_file> (default: erebus_urls.txt)
  • Summary printed to stdout

Usage:
  python d_url_extract.py <erebus_json> [--output FILE] [--full-paths] [--include-farms] [--no-save]

  <erebus_json>      Path to JSON file saved by d_erebus.py (required)
  --output FILE      Output filename (default: erebus_urls_<timestamp>.txt)
  --full-paths       Emit every unique full URL instead of canonical root only
  --include-farms    Include link-farm-flagged hosts (not recommended)
  --no-save          Print URLs to stdout only, do not write a file

For authorized research and investigative use only.
'''

from __future__ import annotations

import json
import sys
import re
from datetime import datetime
from pathlib import Path
from typing import Any

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

BANNER = '''                                   
                                       
██  ██ ▄▄▄▄▄ ▄▄   ▄▄ ▄▄▄▄▄ ▄▄▄▄   ▄▄▄  
██████ ██▄▄  ██▀▄▀██ ██▄▄  ██▄█▄ ██▀██ 
██  ██ ██▄▄▄ ██   ██ ██▄▄▄ ██ ██ ██▀██ 
                                       
Ἡμερα
₩ıƿє ⱥꮤⱥұ ŧħє ѵєıł

Ere̦bus͆ → H̴̼̞̓̾ë̶̤̩̹͘ͅm̷̙̬̠̗̠̈́͠ę̸̨̪̦̊̈́͗̒r̸͕̳̈́̂͛â̶̢̳̙̣̍̀ͅ ̞→ ̢Mnemosyne

'''

DIVIDER = '─' * 62


def parse_args() -> tuple[str, str | None, bool, bool, bool]:
    '''Returns (json_path, output_file, full_paths, include_farms, no_save).'''
    args = sys.argv[1:]

    if not args or args[0] in ('-h', '--help'):
        print(__doc__)
        sys.exit(0)

    json_path = ''
    output_file: str | None = None
    full_paths = '--full-paths' in args
    include_farms = '--include-farms' in args
    no_save = '--no-save' in args

    for i, arg in enumerate(args):
        if arg == '--output':
            try:
                output_file = args[i + 1]
            except IndexError:
                sys.exit(f'\n{R}[ERROR] --output requires a filename argument.{RESET}\n')
        elif not arg.startswith('--'):
            json_path = arg

    if not json_path:
        sys.exit(
            f'\n{R}[ERROR] No input file specified.{RESET}\n'
            f'Usage: python d_url_extract.py <erebus_json> [options]\n'
        )

    return json_path, output_file, full_paths, include_farms, no_save


def load_erebus_json(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        sys.exit(f'\n{R}[ERROR] File not found: {path}{RESET}\n')
    if p.suffix.lower() != '.json':
        print(f'{Y}[WARN] File does not have a .json extension — attempting to parse anyway.{RESET}')
    try:
        with open(p, 'r', encoding='utf-8') as fh:
            data: dict[str, Any] = json.load(fh)
    except json.JSONDecodeError as e:
        sys.exit(f'\n{R}[ERROR] Failed to parse JSON: {e}{RESET}\n')

    # Validate it looks like erebus output
    if 'results' not in data or 'query' not in data:
        sys.exit(
            f'\n{R}[ERROR] This does not look like a d_erebus.py JSON file.\n'
            f'        Expected top-level keys: "query", "results".{RESET}\n'
        )
    return data


def extract_urls(data: dict[str, Any], *, full_paths: bool, include_farms: bool) -> tuple[list[str], int, int]:
    '''
    Returns (url_list, farm_count_excluded, total_results).
    url_list is deduplicated and ordered as encountered.
    '''
    results: list[dict[str, Any]] = data.get('results', [])
    seen: set[str] = set()
    urls: list[str] = []
    farm_count = 0

    for entry in results:
        host: str = str(entry.get('canonical_host', ''))
        is_farm: bool = bool(entry.get('is_link_farm', False))
        full_urls: list[str] = [str(u) for u in entry.get('full_urls', [])]

        if not host:
            continue

        if is_farm and not include_farms:
            farm_count += 1
            continue

        if full_paths:
            for url in full_urls:
                url = url.strip()
                if url and url not in seen:
                    seen.add(url)
                    urls.append(url)
        else:
            # Canonical root only
            root = f'http://{host}/'
            if root not in seen:
                seen.add(root)
                urls.append(root)

    return urls, farm_count, len(results)


def main() -> int:
    json_path, output_file, full_paths, include_farms, no_save = parse_args()

    print(BANNER)
    print(DIVIDER)
    print()

    # Farm warning before loading
    if include_farms:
        print(f'{R}{BOLD}[WARNING] --include-farms is set.{RESET}')
        print(f'{R}  Link-farm hosts produce bloated, low-signal results and may')
        print(f'  waste significant scan time in d_mnemosyne.py --batch.')
        print(f'  Proceed only if you have a specific reason to include them.{RESET}\n')

    print(f'{DIM}Loading: {json_path}{RESET}')
    data = load_erebus_json(json_path)

    query: str = str(data.get('query', 'unknown'))
    run_time: str = str(data.get('run_time', 'unknown'))
    indexes_queried: list[str] = [str(x) for x in data.get('indexes_queried', [])]
    total_raw: int = int(data.get('total_raw', 0))
    total_dedup: int = int(data.get('total_after_dedup', 0))

    print(f'\n  {DIM}Query     :{RESET} {C}{query}{RESET}')
    print(f'  {DIM}Run time  :{RESET} {run_time}')
    print(f'  {DIM}Indexes   :{RESET} {", ".join(indexes_queried) or "unknown"}')
    print(f'  {DIM}Raw hits  :{RESET} {total_raw}   {DIM}After dedup:{RESET} {total_dedup}')
    print()

    urls, farm_count, total_results = extract_urls(
        data, full_paths=full_paths, include_farms=include_farms
    )

    mode_label = 'full paths' if full_paths else 'canonical roots'
    print(f'{DIVIDER}')
    print(f'\n  {DIM}Extraction mode :{RESET} {mode_label}')
    print(f'  {DIM}Total results   :{RESET} {total_results}')

    if farm_count > 0:
        print(f'  {Y}Link farms skipped :{RESET} {Y}{farm_count} host(s) excluded (use --include-farms to override){RESET}')

    print(f'  {G}URLs extracted  :{RESET} {G}{BOLD}{len(urls)}{RESET}')
    print()

    if not urls:
        print(f'{Y}[WARN] No URLs to write. Nothing to do.{RESET}\n')
        return 0

    # Print list
    print(f'{DIVIDER}')
    print(f'\n{B}{BOLD}Extracted URLs:{RESET}\n')
    for i, url in enumerate(urls, 1):
        print(f'  {DIM}{i:>4}.{RESET}  {C}{url}{RESET}')
    print()

    if no_save:
        print(f'{DIM}--no-save: skipping file write.{RESET}\n')
        return 0

    # Write output file
    if output_file is None:
        safe_query = re.sub(r'[^\w.-]', '_', query)[:40]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f'erebus_urls_{safe_query}_{timestamp}.txt'

    with open(output_file, 'w', encoding='utf-8') as fh:
        for url in urls:
            fh.write(url + '\n')

    print(f'{G}  URLs saved → {output_file}{RESET}')
    print(f'{DIM}  Feed to Mnemosyne with: python d_mnemosyne.py --batch {output_file}{RESET}\n')

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f'\n\n{DIM}[Aborted]{RESET}')
        sys.exit(130)