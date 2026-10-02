#!/usr/bin/env python3
"""Generate a readable measured summary; no fabricated scaling/fairness claims."""
import argparse
import collections
import csv
import json
from pathlib import Path
import statistics

p=argparse.ArgumentParser()
p.add_argument('run',type=Path)
a=p.parse_args();root=a.run
m=json.loads((root/'metrics.json').read_text())
c=json.loads((root/'config.json').read_text())
rows=list(csv.DictReader((root/'results.csv').open()))
rounds=list(csv.DictReader((root/'rounds.csv').open()))
lines=[f'Run: {root}',f"Stop: {m['stop_reason']}",f"Completed rounds: {m['completed_rounds']}",
 f"Completed billing periods: {m['completed_billing_periods']}; partial period rounds: {m['partial_period_rounds']}",
 f"Configuration: N={c['meters']}, c={c['committee_size']}, k={c['threshold']}, group={c['group_bits']} bits",
 f"Elapsed wall time incl. shutdown: {m['elapsed_seconds_including_shutdown']:.6f} s",
 f"Parent CPU: {m['parent_cpu_seconds']:.6f} s; all children CPU: {m['children_cpu_seconds']:.6f} s",
 f"Parent peak RSS: {m['parent_max_rss_kib']} KiB; largest child peak RSS: {m['largest_child_max_rss_kib']} KiB",
 'RSS values are process-specific high-water marks, NOT simultaneous total memory.',
 f"Remote protocol messages: {m['protocol_messages_remote']}",
 f"Remote protocol serialized bytes: {m['protocol_wire_bytes_remote']}",
 f"Local self-deliveries excluded from remote totals: {m['local_self_messages']}",
 f"Mean remote message size: {m['protocol_wire_bytes_remote']/max(1,m['protocol_messages_remote']):.2f} bytes",
 'Byte totals include protocol headers and AEAD tags; exclude OS socket overhead and key provisioning.',
 f"Rejected incoming messages: {m['rejected_messages']}"]
for kind in ['spatial','bill']:
    counts=collections.Counter(r['status'] for r in rows if r['kind']==kind)
    lines.append(f'{kind} outputs: {dict(counts)}')
incorrect=[r for r in rows if r['status'].startswith('verified') and r['oracle_match']!='1']
lines.append(f'Accepted outputs disagreeing with independent plaintext oracle: {len(incorrect)}')
if incorrect: lines.append('VALIDATION FAILURE: do not use this run as successful experimental evidence.')
if rounds:
    times=[float(r['processing_seconds']) for r in rounds]
    lines.append(f'Round processing wall seconds: mean={statistics.mean(times):.6f}, median={statistics.median(times):.6f}, max={max(times):.6f}')
    lines.append('Round wall times include selection at billing boundaries and billing at closure; exclude deliberate pacing waits.')
phase=collections.defaultdict(list)
for f in sorted(root.glob('actor-*-timing.csv')):
    for row in csv.DictReader(f.open()):
        phase[row['phase']].append((float(row['wall_seconds']),float(row['cpu_seconds'])))
lines.extend(['','Phase, calls, total measured wall seconds, total measured CPU seconds:'])
for name, samples in sorted(phase.items()):
    lines.append(f'{name}, {len(samples)}, {sum(x[0] for x in samples):.9f}, {sum(x[1] for x in samples):.9f}')
selected=collections.Counter()
periods=set()
for row in csv.DictReader((root/'committees.csv').open()):
    selected[int(row['meter'])]+=1;periods.add(int(row['period']))
lines.extend(['',f'Selection events: {len(periods)}',f'Expected selections/meter under uniform sampling: {len(periods)*c["committee_size"]/c["meters"]:.3f}',
 'Observed selections: '+str({i:selected[i] for i in range(1,c['meters']+1)}),
 'These descriptive counts are not proof of unbiased/adversary-resistant randomness.',
 '', 'Host, compiler and library information: see environment.txt.',
 'Security assumptions, excluded costs and partial-bill semantics: docs/PROTOCOL.md.'])
text='\n'.join(lines)+'\n'
(root/'summary.txt').write_text(text)
print(text)
