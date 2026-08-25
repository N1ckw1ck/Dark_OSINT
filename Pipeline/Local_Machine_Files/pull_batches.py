#!/usr/bin/env python3

'''
pull_batches.py — Pull validated Mnemosyne batches from VPS via SFTP

Connects to the VPS over SFTP, downloads any new batch files from the outbox,
verifies their SHA256 checksums against the sidecar .sha256 files written by
validate_batch.py, and ingests them into Khaeos.

Usage:
  python pull_batches.py [options]

  --vps-ip <ip>       VPS IP address (or set VPS_IP env var)
  --vps-user <user>   SFTP username (default: osint)
  --key <path>        Path to SSH private key (default: ~/.ssh/vps_dark_suite)
  --remote-dir <path> Remote outbox directory (default: /outbox)
  --local-dir <path>  Local download directory (default: Khaeos/batches_for_ingestion) (In this repo)
  --khaeos-db <path>  Path to khaeos.db (default: auto-detect)
  --no-ingest         Download only, skip Khaeos ingest
  --no-delete         Keep files on VPS after successful download (default: delete)
  --dry-run           Show what would happen without doing it

Requires paramiko:
  pip install paramiko
'''

from __future__ import annotations

import hashlib
import os
import sys
import subprocess
from datetime import datetime
from pathlib import Path

try:
    import paramiko
    import paramiko.sftp_client
    import paramiko.ssh_exception
    _paramiko_available = True
except ImportError:
    _paramiko_available = False

# ANSI
R = '\033[91m'
G = '\033[92m'
Y = '\033[93m'
C = '\033[96m'
DIM = '\033[2m'
B = '\033[1m'
RST = '\033[0m'

DIVIDER = '─' * 62

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
DEFAULT_LOCAL_DIR = REPO_ROOT / 'Khaeos' / 'batches_for_ingestion'
DEFAULT_KHAEOS_SCRIPT = REPO_ROOT / 'Khaeos' / 'd_khaeos.py'

# Helpers
def log(msg: str, color: str = '') -> None:
    ts = datetime.now().strftime('%H:%M:%S')
    print(f'{DIM}[{ts}]{RST} {color}{msg}{RST}')


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


# Arg parsing
def parse_args() -> dict[str, object]:
    args = sys.argv[1:]
    opts: dict[str, object] = {
        'vps_ip':     os.environ.get('VPS_IP', ''),
        'vps_user':   'osint',
        'key':        str(Path.home() / '.ssh' / 'vps_dark_suite'),
        'remote_dir': '/outbox',
        'local_dir':  str(DEFAULT_LOCAL_DIR),
        'khaeos_db':  None,
        'no_ingest':  False,
        'no_delete':  False,
        'dry_run':    False,
    }

    if '-h' in args or '--help' in args:
        print(__doc__)
        sys.exit(0)

    i = 0
    while i < len(args):
        a = args[i]
        def next_arg() -> str:
            nonlocal i
            i += 1
            if i >= len(args):
                sys.exit(f'{R}[ERROR] {a} requires an argument.{RST}')
            return args[i]
        if a == '--vps-ip':     opts['vps_ip']     = next_arg()
        elif a == '--vps-user': opts['vps_user']   = next_arg()
        elif a == '--key':      opts['key']         = next_arg()
        elif a == '--remote-dir': opts['remote_dir'] = next_arg()
        elif a == '--local-dir':  opts['local_dir']  = next_arg()
        elif a == '--khaeos-db':  opts['khaeos_db']  = next_arg()
        elif a == '--no-ingest':  opts['no_ingest']  = True
        elif a == '--no-delete':  opts['no_delete']  = True
        elif a == '--dry-run':    opts['dry_run']    = True
        i += 1

    if not opts['vps_ip']:
        sys.exit(
            f'\n{R}[ERROR] VPS IP required.{RST}\n'
            f'  Pass --vps-ip <ip> or set VPS_IP environment variable.\n'
        )

    return opts


# SFTP pull
def pull_batches(opts: dict[str, object]) -> list[Path]:
    '''
    Connect via SFTP, download new batch JSON files + their .sha256 sidecars.
    Verifies checksum after download. Returns list of verified local paths.
    '''
    vps_ip = str(opts['vps_ip'])
    vps_user = str(opts['vps_user'])
    key_path = str(opts['key'])
    remote_dir = str(opts['remote_dir'])
    local_dir = Path(str(opts['local_dir']))
    no_delete = bool(opts['no_delete'])
    dry_run = bool(opts['dry_run'])

    local_dir.mkdir(parents=True, exist_ok=True)

    log(f'Connecting to {vps_user}@{vps_ip}…', C)

    ssh = paramiko.SSHClient() # type: ignore
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy()) # type: ignore

    # Load known_hosts — REJECT if host not known. 
    # On first connection you must add the host manually:
    # ssh-keyscan -H <vps_ip> >> ~/.ssh/known_hosts
    known_hosts = Path.home() / '.ssh' / 'known_hosts'
    if not known_hosts.exists():
        sys.exit(
            f'\n{R}[ERROR] ~/.ssh/known_hosts not found.{RST}\n'
            f'  Add the VPS host key first:\n'
            f'  ssh-keyscan -H {vps_ip} >> ~/.ssh/known_hosts\n'
        )

    ssh.load_host_keys(str(known_hosts))

    try:
        import getpass
        passphrase = getpass.getpass(f'Key passphrase for {opts["key"]}: ')
        ssh.connect(
            hostname=str(opts['vps_ip']),
            username=str(opts['vps_user']),
            key_filename=key_path,
            passphrase=passphrase,
            look_for_keys=False,
            allow_agent=False,
            timeout=15,
        )
    except paramiko.ssh_exception.AuthenticationException: # type: ignore
        sys.exit(f'\n{R}[ERROR] SSH authentication failed. Check key: {key_path}{RST}\n')
    except paramiko.ssh_exception.NoValidConnectionsError as e: # type: ignore
        sys.exit(f'\n{R}[ERROR] Could not connect to {vps_ip}: {e}{RST}\n')
    except Exception as e:
        sys.exit(f'\n{R}[ERROR] SSH connection error: {type(e).__name__}: {e}{RST}\n')

    sftp: paramiko.sftp_client.SFTPClient = ssh.open_sftp()

    try:
        remote_files = sftp.listdir(remote_dir)
    except FileNotFoundError:
        log(f'Remote outbox directory not found: {remote_dir}', R)
        sftp.close(); ssh.close()
        return []

    # Find batch JSON files (not .sha256 sidecars)
    batch_files = sorted(f for f in remote_files if f.endswith('.json'))

    if not batch_files:
        log('No batch files found in remote outbox.', DIM)
        sftp.close(); ssh.close()
        return []

    log(f'Found {len(batch_files)} batch file(s) in remote outbox.', G)

    verified: list[Path] = []

    for filename in batch_files:
        sha_filename = filename + '.sha256'
        if sha_filename not in remote_files:
            log(f'No .sha256 sidecar for {filename} — skipping (not yet validated by VPS)', Y)
            continue

        local_json = local_dir / filename
        local_sha  = local_dir / sha_filename

        # Skip if already downloaded
        if local_json.exists():
            log(f'Already downloaded: {filename} — skipping', DIM)
            continue

        if dry_run:
            log(f'[dry-run] would download: {filename}', DIM)
            continue

        log(f'Downloading: {filename}…', C)
        sftp.get(f'{remote_dir}/{filename}',     str(local_json))
        sftp.get(f'{remote_dir}/{sha_filename}', str(local_sha))

        # Verify checksum
        expected_line = local_sha.read_text(encoding='utf-8').strip()
        expected_hash = expected_line.split()[0] if expected_line else ''
        actual_hash   = sha256_file(local_json)

        if actual_hash != expected_hash:
            log(f'CHECKSUM MISMATCH for {filename} — file may be corrupted or tampered', R)
            log(f'  Expected: {expected_hash}', R)
            log(f'  Actual  : {actual_hash}', R)
         # Quarantine the bad file locally
            bad_dir = local_dir / 'quarantine'
            bad_dir.mkdir(exist_ok=True)
            local_json.rename(bad_dir / filename)
            local_sha.rename(bad_dir / sha_filename)
            continue

        log(f'✓ Checksum verified: {filename}', G)
        verified.append(local_json)

        if not no_delete:
            log(f'  Removing from remote outbox…', DIM)
            sftp.remove(f'{remote_dir}/{filename}')
            sftp.remove(f'{remote_dir}/{sha_filename}')

    sftp.close()
    ssh.close()
    return verified


# Khaeos ingest
def ingest_files(paths: list[Path], opts: dict[str, object]) -> None:
    khaeos_script = DEFAULT_KHAEOS_SCRIPT if DEFAULT_KHAEOS_SCRIPT.exists() else HERE / 'd_khaeos.py'
    if not khaeos_script.exists():
        log(f'Khaeos script not found at {khaeos_script} — skipping ingest', Y)
        return

    for path in paths:
        log(f'Ingesting into Khaeos: {path.name}…', C)
        cmd = [sys.executable, str(khaeos_script), '--ingest', str(path)]
        if opts.get('khaeos_db'):
            cmd += ['--db', str(opts['khaeos_db'])]
        result = subprocess.run(cmd)
        if result.returncode == 0:
            log(f'✓ Ingested: {path.name}', G)
        else:
            log(f'Khaeos ingest returned code {result.returncode} for {path.name}', Y)


# Main
def main() -> int:
    if not _paramiko_available:
        print(f'{R}[ERROR] paramiko is required:{RST}')
        print(f'  pip install paramiko\n')
        return 1

    opts = parse_args()

    print(f'\n{DIVIDER}')
    print(f'{B}{C}  Khaeos Batch Pull{RST}')
    print(f'{DIVIDER}')
    print(f'  {DIM}VPS       :{RST} {opts["vps_user"]}@{opts["vps_ip"]}')
    print(f'  {DIM}Key       :{RST} {opts["key"]}')
    print(f'  {DIM}Remote    :{RST} {opts["remote_dir"]}')
    print(f'  {DIM}Local     :{RST} {opts["local_dir"]}')
    print(f'  {DIM}Ingest    :{RST} {"no" if opts["no_ingest"] else "yes"}')
    print(f'  {DIM}Delete    :{RST} {"no" if opts["no_delete"] else "yes (after download)"}')
    if opts['dry_run']:
        print(f'  {Y}DRY RUN — no changes will be made{RST}')
    print()

    verified = pull_batches(opts)

    if not verified:
        log('No new verified files downloaded.', DIM)
        return 0

    log(f'{len(verified)} file(s) downloaded and verified.', G)

    if not opts['no_ingest'] and not opts['dry_run']:
        ingest_files(verified, opts)

    print(f'\n{DIVIDER}')
    print(f'{G}  Done. {len(verified)} batch(es) processed.{RST}')
    print(f'{DIVIDER}\n')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f'\n{DIM}[Aborted]{RST}')
        sys.exit(130)
