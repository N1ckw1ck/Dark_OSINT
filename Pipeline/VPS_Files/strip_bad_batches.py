#!/usr/bin/env python3
'''
Removes one report by index number from a Mnemosyne quarantined batch file, and updates
total_targets/summary/groups in the batch file to maintain data quality, overwriting
the file in place.

Workflow:
    If the quarantine folder is filling up:
    Manually review batches, if false positives/noise, run this script on the quarantined batch.
    Re-run validate_batch.py on it afterward to send it on its way.

Usage:
    python strip_bad_batches.py <batch.json> <report_index>

        <batch.json>    (filepath)
        <report_index>  (integer)

    example:
        python strip_bad_batches.py \
          /home/osintd/dark_osint/output/mnemosyne/quarantine/QUARANTINE_<PLACEHOLDER>_Mnemosyne_batch_<PLACEHOLDER>.json \
          2005
'''

import json
import sys

path, index = sys.argv[1], int(sys.argv[2])

with open(path, encoding='utf-8') as f:
    data = json.load(f)

removed = data['reports'].pop(index)
target = removed.get('target', '(no target field)')

data['total_targets'] = len(data['reports'])
for group in data.get('groups', {}).values():
    if target in group:
        group.remove(target)
for key, group in data.get('groups', {}).items():
    if key in data.get('summary', {}):
        data['summary'][key] = len(group)

with open(path, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print(f'Removed reports[{index}] (target: {target})')
print(f'New total_targets: {data["total_targets"]}')