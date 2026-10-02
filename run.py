#!/usr/bin/env python3
"""Interactive launcher; replaces itself with the C process so Ctrl+C reaches it."""
from pathlib import Path
import os
import shlex

root=Path(__file__).resolve().parent
os.chdir(root)
if not (root/'meter-sim').exists():
    raise SystemExit('Build first: make')

def ask(label, default):
    return input(f'{label} [{default}]: ').strip() or str(default)

print('Raspberry Pi smart-meter simulator — billing-period committees')
print('1. Smoke test: 4 meters, 3-member committee, k=2, 6 rounds, 3 rounds/bill')
print('2. Experiment: 20 meters, 10-member committee, k=6, 144 rounds, 12 rounds/bill')
print('3. Customize / run until stopped')
choice=ask('Select', '1')
if choice=='1':
    args=['--meters','4','--committee','3','--threshold','2','--rounds','6','--billing-rounds','3']
elif choice=='2':
    args=['--meters','20','--committee','10','--threshold','6','--rounds','144','--billing-rounds','12']
elif choice=='3':
    args=[]
    for label, flag, default in [
        ('Meters','--meters',20),('Committee size','--committee',10),('Threshold k','--threshold',6),
        ('Maximum rounds (0 = until stopped)','--rounds',0),
        ('Readings per billing period','--billing-rounds',12),
        ('Minimum seconds between round starts','--interval',1),
        ('Wall-clock limit, seconds (0 = none)','--duration',0),
        ('Historical seconds per reading','--sample-seconds',300),
        ('Repeating tariffs, microCAD/Wh','--tariffs','98,157,203'),
        ('Synthetic seed (NOT cryptographic randomness)','--seed',42),
        ('Scenario: none/tamper/replay/bad-share/bad-aggregate/drop-share','--attack','none'),
        ('Attack round (zero-based)','--attack-round',2),
    ]:
        args.extend([flag,ask(label,default)])
    filename=input('CSV data file (Enter for synthetic): ').strip()
    if filename: args.extend(['--csv',filename])
else:
    raise SystemExit('Choose 1, 2, or 3.')
print('Command:',shlex.join(['./meter-sim',*args]),flush=True)
print('Stop: Ctrl+C, or q followed by Enter. Wait for the Saved message.',flush=True)
os.execv(str(root/'meter-sim'),['meter-sim',*args])
