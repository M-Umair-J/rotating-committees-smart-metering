"""System tests. Host outputs are correctness evidence, NOT Pi measurements."""
import csv
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / 'meter-sim'

def read_results(p):
    return list(csv.DictReader((p / 'results.csv').open()))

def run(base, name, *args):
    out = base / name
    cmd = [str(EXE), '--meters', '4', '--committee', '3', '--threshold', '2',
           '--rounds', '4', '--billing-rounds', '3', '--out', str(out), *map(str, args)]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, timeout=90)
    return out, read_results(out), json.loads((out / 'metrics.json').read_text())

with tempfile.TemporaryDirectory(prefix='pi-meter-tests-') as tmp:
    base = Path(tmp)
    out, rows, met = run(base, 'honest')
    assert len(rows) == 12
    assert all(r['oracle_match'] == '1' and r['commitment_ok'] == '1' for r in rows)
    assert sum(r['status'] == 'verified_partial' for r in rows) == 4
    assert met['completed_billing_periods'] == 1 and met['partial_period_rounds'] == 1
    groups = list(csv.DictReader((out / 'committees.csv').open()))
    assert len(groups) == 6 and {r['period'] for r in groups} == {'0', '1'}
    params = dict(line.strip().split('=', 1) for line in (out / 'public_parameters.txt').read_text().splitlines())
    p, q, g, h = (int(params[k], 16) for k in ('p', 'q', 'g', 'h'))
    assert q == (p-1)//2 and p.bit_length() == 2048
    assert h == pow(int.from_bytes(hashlib.shake_256(b'pi-meter-sim-v1/pedersen-h').digest(256), 'big'), 2, p)
    v = subprocess.check_output([str(ROOT / 'crypto-test')], text=True).splitlines()[0].split('=')[1]
    assert int(v, 16) == pow(g, 5, p)*pow(h, 7, p)%p
    wire = list(csv.DictReader((out / 'messages.csv').open()))
    remote = [r for r in wire if r['sender'] != r['recipient']]
    assert len(remote) == met['protocol_messages_remote']
    assert sum(int(r['wire_bytes']) for r in remote) == met['protocol_wire_bytes_remote']
    print('PASS honest, partial closure, independent commitment, traffic accounting')

    for attack in ('tamper', 'replay', 'bad-share', 'bad-aggregate', 'drop-share'):
        out, rows, met = run(base, attack, '--attack', attack, '--attack-round', 1)
        if attack == 'replay':
            assert met['rejected_messages'] == 1 and all(r['oracle_match'] == '1' for r in rows)
        else:
            assert met['incomplete_or_rejected_outputs'] > 0
            assert not any(r['status'].startswith('verified') and r['oracle_match'] != '1' for r in rows)
        if attack == 'tamper': assert met['rejected_messages'] == 1
        print('PASS', attack)

    dataset = base / 'input.csv'
    dataset.write_text('round,sm1,sm2,sm3,sm4\n0,1000,2000,3000,4000\n1,2000,3000,4000,5000\n')
    _, rows, met = run(base, 'csv', '--csv', dataset, '--tariffs', '100,200', '--rounds', 0)
    assert met['stop_reason'] == 'dataset_end'
    assert [int(r['value']) for r in rows if r['kind'] == 'bill'] == [500000,800000,1100000,1400000]
    assert all(r['oracle_match']=='1' for r in rows)
    print('PASS known CSV bills and EOF finalization')

    _, rows, met = run(base, 'zero', '--csv', dataset, '--tariffs', '0', '--billing-rounds', 1)
    assert all(int(r['value'])==0 for r in rows if r['kind']=='bill')
    print('PASS zero tariff')

    _, rows, met = run(base, 'larger', '--meters', 10, '--committee', 6, '--threshold', 4, '--rounds', 2)
    assert all(r['oracle_match']=='1' for r in rows)
    print('PASS 10 actors, 4-of-6 reconstruction')

    for stop in ('signal', 'q'):
        out = base / stop
        proc = subprocess.Popen([str(EXE),'--meters','4','--committee','3','--threshold','3',
            '--rounds','0','--interval','1','--billing-rounds','20','--out',str(out)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, start_new_session=True)
        for line in proc.stdout:
            if line.startswith('Round 1 complete'):
                if stop=='signal': os.killpg(proc.pid,signal.SIGINT)
                else: proc.stdin.write('q\n');proc.stdin.flush()
                break
        proc.communicate(timeout=30)
        assert proc.returncode==0
        met=json.loads((out/'metrics.json').read_text())
        assert met['stop_reason']=='user_stop' and met['completed_rounds']>=1
        assert all(r['status']=='verified_partial' for r in read_results(out) if r['kind']=='bill')
        print('PASS graceful', stop)

    # Interrupt DURING protocol traffic, not only during interval pacing.
    out = base / 'midround'
    proc = subprocess.Popen([str(EXE),'--meters','20','--committee','10','--threshold','6',
        '--rounds','0','--billing-rounds','10','--out',str(out)],
        stdout=subprocess.DEVNULL, start_new_session=True)
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        f=out/'messages.csv'
        if f.exists() and f.stat().st_size>1000:
            os.killpg(proc.pid,signal.SIGINT)
            break
        time.sleep(.005)
    else:
        proc.kill()
        raise AssertionError('No protocol progress')
    assert proc.wait(timeout=60)==0
    met=json.loads((out/'metrics.json').read_text())
    assert met['stop_reason']=='user_stop' and met['completed_rounds']>=1
    assert all(r['oracle_match']=='1' for r in read_results(out))
    print('PASS interrupt during active round (20 meters)')

    _, rows, met = run(base,'duration','--rounds',0,'--interval',1,'--duration',0.2)
    assert met['stop_reason']=='duration_limit' and met['completed_rounds']>=1
    print('PASS wall-clock limit')
print('All integration tests PASS')
