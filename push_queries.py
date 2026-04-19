#!/usr/bin/env python3

'''
push_queries.py — Push updated query list to VPS

Manages the queries.txt file on the VPS that pipeline.py reads from.
Supports viewing current queries, replacing them, or appending new ones.

Usage:
  python push_queries.py --show
  python push_queries.py --set "forums" "markets" "chatroom"
  python push_queries.py --add "pastebin" "dump"
  python push_queries.py --remove "chatroom"
  python push_queries.py --file my_queries.txt
  python push_queries.py --schedule monday "forums" "markets" \
                                    thursday "pastebin" "dump"

Options:
  --vps-ip <ip>     VPS IP (or set VPS_IP env var)
  --vps-user <user> SSH username (default: root)
  --key <path>      SSH private key (default: ~/.ssh/vultr_khaeos)
  --show            Print current queries on VPS
  --set <q> [q...]  Replace all queries with these
  --add <q> [q...]  Append queries to existing list
  --remove <q>      Remove a specific query
  --file <path>     Replace queries with contents of a local file
  --schedule <day> <q> [q...] <day> <q> [q...]
                    Set a weekly schedule (writes day-specific query files
                    and installs a cron that picks the right file each day)
  --dry-run         Show what would be pushed without connecting
'''

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path
from io import StringIO

try:
    import paramiko  # type: ignore
    import paramiko.sftp_client  # type: ignore
    _paramiko_available = True
except ImportError:
    _paramiko_available = False

R   = '\033[91m'
G   = '\033[92m'
Y   = '\033[93m'
C   = '\033[96m'
DIM = '\033[2m'
B   = '\033[1m'
RST = '\033[0m'

REMOTE_CONFIG  = '/home/osintd/dark_osint/config'
REMOTE_QUERIES = f'{REMOTE_CONFIG}/queries.txt'

DAYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
DAY_CRON_NUMS = {
    'monday': '1', 'tuesday': '2', 'wednesday': '3', 'thursday': '4',
    'friday': '5', 'saturday': '6', 'sunday': '0',
}


def log(msg: str, color: str = '') -> None:
    ts = datetime.now().strftime('%H:%M:%S')
    print(f'{DIM}[{ts}]{RST} {color}{msg}{RST}')


def parse_args() -> dict[str, object]:
    args = sys.argv[1:]
    if not args or '-h' in args or '--help' in args:
        print(__doc__)
        sys.exit(0)

    opts: dict[str, object] = {
        'vps_ip':   os.environ.get('VPS_IP', ''),
        'vps_user': 'root',
        'key':      str(Path.home() / '.ssh' / 'vultr_khaeos'),
        'action':   None,
        'queries':  [],
        'file':     None,
        'schedule': {},
        'dry_run':  False,
    }

    i = 0
    while i < len(args):
        a = args[i]
        def nxt() -> str:
            nonlocal i
            i += 1
            if i >= len(args):
                sys.exit(f'{R}[ERROR] {a} requires an argument.{RST}')
            return args[i]

        if a == '--vps-ip':     opts['vps_ip']   = nxt()
        elif a == '--vps-user': opts['vps_user'] = nxt()
        elif a == '--key':      opts['key']       = nxt()
        elif a == '--dry-run':  opts['dry_run']   = True
        elif a == '--show':     opts['action']    = 'show'
        elif a == '--file':
            opts['action'] = 'file'
            opts['file']   = nxt()
        elif a == '--set':
            opts['action'] = 'set'
            queries: list[str] = []
            i += 1
            while i < len(args) and not args[i].startswith('--'):
                queries.append(args[i]); i += 1
            opts['queries'] = queries
            continue
        elif a == '--add':
            opts['action'] = 'add'
            queries = []
            i += 1
            while i < len(args) and not args[i].startswith('--'):
                queries.append(args[i]); i += 1
            opts['queries'] = queries
            continue
        elif a == '--remove':
            opts['action'] = 'remove'
            opts['queries'] = [nxt()]
        elif a == '--schedule':
            opts['action'] = 'schedule'
            schedule: dict[str, list[str]] = {}
            current_day = ''
            i += 1
            while i < len(args) and not args[i].startswith('--'):
                token = args[i].lower()
                if token in DAYS:
                    current_day = token
                    schedule[current_day] = []
                elif current_day:
                    schedule[current_day].append(args[i])
                i += 1
            opts['schedule'] = schedule
            continue
        i += 1

    if not opts['action']:
        sys.exit(f'{R}[ERROR] No action specified. Use --show, --set, --add, --remove, --file, or --schedule.{RST}')

    if not opts['vps_ip'] and opts['action'] != 'dry_run':
        sys.exit(f'{R}[ERROR] --vps-ip required (or set VPS_IP env var).{RST}')

    return opts


def make_ssh(opts: dict[str, object]) -> 'paramiko.SSHClient':  # type: ignore[name-defined]
    ssh = paramiko.SSHClient()  # type: ignore[misc]
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())  # type: ignore[misc]
    known_hosts = Path.home() / '.ssh' / 'known_hosts'
    if not known_hosts.exists():
        sys.exit(f'{R}[ERROR] ~/.ssh/known_hosts not found. Run ssh-keyscan first.{RST}')
    ssh.load_host_keys(str(known_hosts))
    ssh.connect(
        hostname=str(opts['vps_ip']),
        username=str(opts['vps_user']),
        key_filename=str(opts['key']),
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    return ssh  # type: ignore[return-value]


def read_remote_queries(sftp: 'paramiko.sftp_client.SFTPClient') -> list[str]:  # type: ignore[name-defined]
    try:
        buf = StringIO()
        with sftp.open(REMOTE_QUERIES, 'r') as fh:  # type: ignore[misc]
            buf.write(fh.read().decode('utf-8'))  # type: ignore[misc]
        lines = buf.getvalue().splitlines()
        return [l for l in lines if l.strip() and not l.strip().startswith('#')]
    except FileNotFoundError:
        return []


def write_remote_queries(
    sftp: 'paramiko.sftp_client.SFTPClient',  # type: ignore[name-defined]
    queries: list[str],
    remote_path: str = REMOTE_QUERIES,
) -> None:
    content = '# Khaeos pipeline query list\n'
    content += f'# Updated: {datetime.now().isoformat()}\n'
    content += '# One query per line. Lines starting with # are ignored.\n\n'
    content += '\n'.join(q.strip() for q in queries if q.strip())
    content += '\n'
    with sftp.open(remote_path, 'w') as fh:  # type: ignore[misc]
        fh.write(content.encode('utf-8'))  # type: ignore[misc]


def build_schedule_cron(schedule: dict[str, list[str]]) -> str:
    '''
    Returns cron lines that run pipeline.py with the right queries
    for each day of the week.
    '''
    lines: list[str] = []
    venv_py = '/home/osintd/venv/bin/python'
    work_dir = '/home/osintd/dark_osint'
    for day, queries in schedule.items():
        dow = DAY_CRON_NUMS[day]
        quoted = ' '.join(f'"{q}"' for q in queries)
        line = (
            f'0 2 * * {dow} cd {work_dir} && '
            f'{venv_py} pipeline.py {quoted} --pages 3 && '
            f'{venv_py} validate_batch.py '
            f'$(ls -t output/Mnemosyne_batch_*.json 2>/dev/null | head -1) '
            f'--outbox /home/osint/outbox'
        )
        lines.append(f'# {day.capitalize()}')
        lines.append(line)
    return '\n'.join(lines)


def main() -> int:
    if not _paramiko_available:
        print(f'{R}[ERROR] paramiko required: pip install paramiko{RST}')
        return 1

    opts = parse_args()
    dry_run = bool(opts['dry_run'])
    action  = str(opts['action'])

    print(f'\n{DIM}{"─" * 60}{RST}')
    print(f'{B}  push_queries — {action}{RST}')
    print(f'{DIM}{"─" * 60}{RST}')

    if action == 'show':
        if dry_run:
            log('[dry-run] would show remote queries', DIM); return 0
        ssh = make_ssh(opts)
        sftp: paramiko.sftp_client.SFTPClient = ssh.open_sftp()  # type: ignore[misc]
        queries = read_remote_queries(sftp)
        sftp.close(); ssh.close()
        if not queries:
            log('No queries found on VPS.', Y)
        else:
            print(f'\n{G}  Current queries ({len(queries)}):{RST}')
            for i, q in enumerate(queries, 1):
                print(f'  {DIM}{i:>3}.{RST}  {C}{q}{RST}')
        print()
        return 0

    if action == 'set':
        new_queries: list[str] = list(opts['queries'])  # type: ignore[arg-type]
        if not new_queries:
            sys.exit(f'{R}[ERROR] --set requires at least one query.{RST}')
        if dry_run:
            log(f'[dry-run] would set {len(new_queries)} queries:', DIM)
            for q in new_queries: print(f'  {C}{q}{RST}')
            return 0
        ssh = make_ssh(opts)
        sftp = ssh.open_sftp()  # type: ignore[misc]
        write_remote_queries(sftp, new_queries)
        sftp.close(); ssh.close()
        log(f'Set {len(new_queries)} queries on VPS.', G)

    elif action == 'add':
        add_queries: list[str] = list(opts['queries'])  # type: ignore[arg-type]
        if dry_run:
            log(f'[dry-run] would add: {add_queries}', DIM); return 0
        ssh = make_ssh(opts)
        sftp = ssh.open_sftp()  # type: ignore[misc]
        existing = read_remote_queries(sftp)
        merged = existing + [q for q in add_queries if q not in existing]
        write_remote_queries(sftp, merged)
        sftp.close(); ssh.close()
        log(f'Added {len(add_queries)} queries. Total: {len(merged)}.', G)

    elif action == 'remove':
        remove_q: str = str(list(opts['queries'])[0])  # type: ignore[arg-type]
        if dry_run:
            log(f'[dry-run] would remove: {remove_q}', DIM); return 0
        ssh = make_ssh(opts)
        sftp = ssh.open_sftp()  # type: ignore[misc]
        existing = read_remote_queries(sftp)
        updated = [q for q in existing if q.lower() != remove_q.lower()]
        write_remote_queries(sftp, updated)
        sftp.close(); ssh.close()
        log(f'Removed "{remove_q}". Remaining: {len(updated)}.', G)

    elif action == 'file':
        local_file = Path(str(opts['file']))
        if not local_file.exists():
            sys.exit(f'{R}[ERROR] File not found: {local_file}{RST}')
        file_queries = [
            l.strip() for l in local_file.read_text().splitlines()
            if l.strip() and not l.strip().startswith('#')
        ]
        if dry_run:
            log(f'[dry-run] would push {len(file_queries)} queries from {local_file}', DIM)
            for q in file_queries: print(f'  {C}{q}{RST}')
            return 0
        ssh = make_ssh(opts)
        sftp = ssh.open_sftp()  # type: ignore[misc]
        write_remote_queries(sftp, file_queries)
        sftp.close(); ssh.close()
        log(f'Pushed {len(file_queries)} queries from {local_file.name}.', G)

    elif action == 'schedule':
        schedule: dict[str, list[str]] = dict(opts['schedule'])  # type: ignore[arg-type]
        if not schedule:
            sys.exit(f'{R}[ERROR] No schedule entries parsed.{RST}')
        cron_block = build_schedule_cron(schedule)
        print(f'\n{G}  Cron block to install on VPS (crontab -u osintd -e):{RST}\n')
        print(f'{DIM}{cron_block}{RST}\n')
        if not dry_run:
            ssh = make_ssh(opts)
            sftp = ssh.open_sftp()  # type: ignore[misc]
            # Write each day's queries to a named file
            for day, queries in schedule.items():
                remote_path = f'{REMOTE_CONFIG}/queries_{day}.txt'
                write_remote_queries(sftp, queries, remote_path)
                log(f'Wrote {len(queries)} queries → queries_{day}.txt', G)
            sftp.close(); ssh.close()
            log('Schedule files pushed. Install the cron block shown above.', Y)

    print()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f'\n{DIM}[Aborted]{RST}')
        sys.exit(130)