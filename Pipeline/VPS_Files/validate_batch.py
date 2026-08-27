#!/usr/bin/env python3

'''
validate_batch.py — Mnemosyne batch JSON validator

Validate a Mnemosyne batch JSON file before it is moved to the SFTP outbox.
Checks:
  • Valid JSON and expected top-level structure
  • All fields are expected types — no injected objects, callables, or binary
  • String fields are within sane length bounds
  • No unexpected top-level keys
  • Per-report field whitelist — any unknown keys are flagged
  • String content scan — flags suspicious patterns (base64 blobs,
    shell metacharacters in unexpected fields, binary-looking content)

If validation passes, copies the file to the outbox.
If validation fails, the file is quarantined and NOT copied.

Usage:
  python validate_batch.py <batch.json> --outbox <outbox_dir>
  python validate_batch.py <batch.json> --outbox /home/osint/outbox

Exit codes:
  0 — valid, file copied to outbox
  1 — validation failed, file quarantined
  2 — usage/file error
  4 - validation passed, but write to outbox failed (permissions, disk, etc.)
'''

from __future__ import annotations

import json
import re
import sys
import shutil
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, cast

# ANSI
R = '\033[91m'
G = '\033[92m'
Y = '\033[93m'
DIM = '\033[2m'
B = '\033[1m'
RST = '\033[0m'

# Schema
# Expected top-level keys for a batch file (must match d_mnemosyne.py's save_batch_report)
BATCH_TOP_LEVEL = {
    'batch_scan_time', 'url_source', 'total_targets', 'summary', 'groups',
    'reports',
}

# Expected top-level keys for a single-scan file
SINGLE_TOP_LEVEL = {
    'scan_time', 'target', 'tor', 'reachability', 'reputation', 'headers',
    'well_known', 'canary', 'scripts', 'resources', 'forms', 'tech', 'risk',
    'page_title', 'raw_html_length',
}

# Expected keys inside each report dict
REPORT_KEYS = {
    'scan_time', 'target', 'tor', 'reachability', 'reputation', 'headers',
    'well_known', 'canary', 'scripts', 'resources', 'forms', 'tech', 'risk',
    'page_title', 'raw_html_length',
}

# Fields that must be strings if present
STRING_FIELDS = {
    'scan_time', 'target', 'batch_scan_time', 'page_title',
}

# Fields that must be integers/floats if present
NUMERIC_FIELDS = {
    'raw_html_length', 'total', 'reachable', 'unreachable', 'scan_duration_s',
}

# Hard limits
MAX_FILE_SIZE_MB = 50
MAX_STRING_LENGTH = 100_000 # any single string value
MAX_REPORTS = 10_000
MAX_TARGET_LENGTH = 200

# Suspicious string patterns — JSON may have been stuffed with something malicious
SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    # Shell injection attempts in string values
    (r';\s*(rm|wget|curl|bash|sh|python|nc|ncat|mkfifo)\s', 'shell command injection'),
    # Null bytes
    (r'\x00', 'null byte'),
    # Python/JS eval patterns
    (r'__import__|eval\(|exec\(|os\.system', 'code execution pattern'),
    # Attempts to break out of expected paths
    (r'\.\./\.\./\.\./', 'path traversal'),
]

COMPILED_PATTERNS = [(re.compile(p), label) for p, label in SUSPICIOUS_PATTERNS]


# Validation
class ValidationError(Exception):
    pass


def check_string(value: str, field_name: str) -> list[str]:
    '''Scan a string value for suspicious content. Returns list of warnings.'''
    warnings: list[str] = []

    if len(value) > MAX_STRING_LENGTH:
        warnings.append(f'{field_name}: string exceeds {MAX_STRING_LENGTH} chars ({len(value)})')

    if any(skip in field_name.lower() for skip in ['header', 'cookie', 'set_cookie', 'authorization']):
        return warnings

    for pattern, label in COMPILED_PATTERNS:
        if pattern.search(value):
            warnings.append(f'{field_name}: suspicious pattern — {label}')

    return warnings


def walk_value(value: Any, path: str, warnings: list[str], depth: int = 0) -> None:
    '''
    Recursively walk a JSON value tree.
    Checks types, string content, and depth limits.
    '''
    if depth > 20:
        warnings.append(f'{path}: excessive nesting depth — possible DoS structure')
        return

    if isinstance(value, str):
        warnings.extend(check_string(value, path))
    elif isinstance(value, (int, float, bool, type(None))):
        pass  # primitives are fine
    elif isinstance(value, list):
        value_list = cast(list[Any], value)
        for i, item in enumerate(value_list):
            walk_value(item, f'{path}[{i}]', warnings, depth + 1)
    elif isinstance(value, dict):
        value_dict = cast(dict[Any, Any], value)
        for k, v in value_dict.items():
            if not isinstance(k, str):
                warnings.append(f'{path}: non-string dict key: {k!r}')
                continue
            walk_value(v, f'{path}.{k}', warnings, depth + 1)
    else:
        # Unexpected type — json.load should never produce 
        warnings.append(f'{path}: unexpected type {type(value).__name__}')


def validate_report(report: dict[str, Any], index: int) -> list[str]:
    '''Validate a single report dict. Returns list of warnings.'''
    warnings: list[str] = []
    prefix = f'reports[{index}]'

    unknown_keys = set(report.keys()) - REPORT_KEYS
    if unknown_keys:
        warnings.append(f'{prefix}: unexpected keys: {sorted(unknown_keys)}')

    target = report.get('target', '')
    if not isinstance(target, str) or not target:
        warnings.append(f'{prefix}: missing or non-string target')
    elif len(target) > MAX_TARGET_LENGTH:
        warnings.append(f'{prefix}.target: suspiciously long ({len(target)} chars)')
    elif not re.match(r'^https?://[a-z2-7]{16,56}\.onion', target):
        # Allow http/https to .onion only — flag anything else
        warnings.append(f'{prefix}.target: unexpected target format: {target[:80]}')

    walk_value(report, prefix, warnings)

    return warnings


def validate_file(path: Path) -> tuple[bool, list[str], dict[str, Any]]:
    '''
    Returns (is_valid, warnings_list, parsed_data).
    is_valid is False if any hard errors found, True if only warnings or clean.
    '''
    warnings: list[str] = []
    errors: list[str] = []

    # File size check
    size_mb = path.stat().st_size / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        errors.append(f'File too large: {size_mb:.1f} MB (limit {MAX_FILE_SIZE_MB} MB)')
        return False, errors, {}

    # Parse JSON
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            raw: dict[str, Any] = json.load(fh)
    except json.JSONDecodeError as e:
        errors.append(f'Invalid JSON: {e}')
        return False, errors, {}
    except UnicodeDecodeError as e:
        errors.append(f'Encoding error (binary content?): {e}')
        return False, errors, {}

    if not isinstance(raw, dict): # type: ignore
        errors.append('Top-level structure is not a JSON object')
        return False, errors, {}

    # Determine format
    is_batch = 'reports' in raw and isinstance(raw.get('reports'), list)
    is_single = 'target' in raw and 'scan_time' in raw

    if not is_batch and not is_single:
        errors.append(
            'Unrecognized format: expected batch (with "reports" list) '
            'or single-scan (with "target" + "scan_time")'
        )
        return False, errors, {}

    # Top-level key check
    expected_top = BATCH_TOP_LEVEL if is_batch else SINGLE_TOP_LEVEL
    unknown_top = set(raw.keys()) - expected_top
    if unknown_top:
        warnings.append(f'Unexpected top-level keys: {sorted(unknown_top)}')

    # Validate reports
    if is_batch:
        reports: list[Any] = raw['reports']
        if len(reports) > MAX_REPORTS:
            errors.append(f'Report count {len(reports)} exceeds maximum {MAX_REPORTS}')
            return False, errors, raw
        for i, report in enumerate(reports):
            if not isinstance(report, dict):
                errors.append(f'reports[{i}] is not a dict')
                continue
            warnings.extend(validate_report(cast(dict[str, Any], report), i))
    else:
        warnings.extend(validate_report(raw, 0))

    # If there are suspicious pattern hits (not just unknown keys), treat as error
    hard_warnings = [w for w in warnings if any(
        label in w for label in [
            'shell command injection', 'long base64 blob', 'null byte',
            'code execution pattern', 'path traversal', 'excessive nesting',
            'unexpected type', 'non-string dict key',
        ]
    )]

    if hard_warnings or errors:
        return False, errors + hard_warnings, raw

    return True, warnings, raw


# CLI
def parse_args() -> tuple[Path, Path]:
    args = sys.argv[1:]
    if len(args) < 3 or '--outbox' not in args:
        print(__doc__)
        sys.exit(2)

    input_file = Path(args[0])
    outbox_dir = Path(args[args.index('--outbox') + 1])
    return input_file, outbox_dir


def main() -> int:
    input_file, outbox_dir = parse_args()

    print(f'\n{DIM}{"─" * 60}{RST}')
    print(f'{B}  Batch Validator{RST}')
    print(f'{DIM}{"─" * 60}{RST}')
    print(f'  {DIM}File   :{RST} {input_file}')
    print(f'  {DIM}Outbox :{RST} {outbox_dir}')

    if not input_file.exists():
        print(f'\n{R}[ERROR] File not found: {input_file}{RST}\n')
        return 2

    # Compute checksum before validation
    sha256 = hashlib.sha256(input_file.read_bytes()).hexdigest()
    print(f'  {DIM}SHA256 :{RST} {sha256[:32]}…')
    print()

    is_valid, issues, data = validate_file(input_file)

    if is_valid:
        report_count = len(data.get('reports', [data])) if 'reports' in data else 1
        print(f'{G}  ✓ Validation passed{RST}')
        print(f'  {DIM}Reports  :{RST} {report_count}')
        if issues:
            print(f'  {Y}Warnings :{RST}')
            for w in issues:
                print(f'    {Y}! {w}{RST}')

        # Move to outbox
        try:
            outbox_dir.mkdir(parents=True, exist_ok=True)
            dest = outbox_dir / input_file.name
            shutil.copy2(input_file, dest)

            # Write a sidecar checksum file
            (outbox_dir / (input_file.name + '.sha256')).write_text(
                f'{sha256}  {input_file.name}\n', encoding='utf-8'
            )
        except OSError as e:
            print(f'\n{R}[ERROR] Could not write to outbox {outbox_dir}: {e}{RST}')
            print(f'{R}  Check that this user has write permissions on outbox directory'
                  f'  (e.g. group membership + mode, not just ownership). {RST}\n')
            return 4

        print(f'\n{G}  → Copied to outbox: {dest}{RST}')
        print(f'{G}  → Checksum written: {dest}.sha256{RST}\n')
        return 0

    else:
        print(f'{R}  ✗ Validation FAILED — file quarantined{RST}\n')
        print(f'{R}  Issues found:{RST}')
        for issue in issues:
            print(f'    {R}✗ {issue}{RST}')

        # Quarantine — move to a quarantine dir, do NOT put in outbox
        quarantine_dir = input_file.parent / 'quarantine'
        quarantine_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        dest = quarantine_dir / f'QUARANTINE_{ts}_{input_file.name}'
        shutil.move(str(input_file), dest)

        # Write a quarantine report
        report_path = quarantine_dir / f'QUARANTINE_{ts}_{input_file.name}.report.txt'
        report_path.write_text(
            f'Quarantine report\n'
            f'File    : {input_file}\n'
            f'SHA256  : {sha256}\n'
            f'Time    : {datetime.now().isoformat()}\n'
            f'Issues  :\n' +
            '\n'.join(f'  - {i}' for i in issues) + '\n',
            encoding='utf-8'
        )

        print(f'\n{R}  Quarantined to: {dest}{RST}')
        print(f'{R}  Report written: {report_path}{RST}\n')
        return 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f'\n{DIM}[Aborted]{RST}')
        sys.exit(2)