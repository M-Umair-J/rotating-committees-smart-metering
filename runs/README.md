# Archived experiment

The directory [`20261001-104551-2692/`](20261001-104551-2692/) contains the results of the Raspberry Pi 4 experiment completed on 1 October 2026.

The simulator ran for approximately 75 minutes with 20 smart-meter processes, a 10-member committee, and a reconstruction threshold of 6. It completed 150 reporting rounds across 15 billing periods, with ten rounds per period. Committee selection occurred at the start of each billing period, and membership remained fixed throughout that period.

All 150 spatial aggregates and 300 customer bills matched independent plaintext reference calculations. The run used synthetic readings with seed 42, repeating tariffs of 98, 157, and 203 microCAD/Wh, and no injected faults.

## Files

| File | Contents |
|---|---|
| [`config.json`](20261001-104551-2692/config.json) | Complete run configuration |
| [`environment.txt`](20261001-104551-2692/environment.txt) | Hardware, operating system, compiler, and library details |
| [`metrics.json`](20261001-104551-2692/metrics.json) | Processing time, CPU usage, memory peaks, message counts, and bytes transferred |
| [`results.csv`](20261001-104551-2692/results.csv) | Reconstructed spatial totals and customer bills, verification statuses, and reference comparisons |
| [`summary.txt`](20261001-104551-2692/summary.txt) | Human-readable results summary |
| [`rounds.csv`](20261001-104551-2692/rounds.csv) | Per-round processing times and tariffs |
| [`committees.csv`](20261001-104551-2692/committees.csv) | Committee membership for each billing period |
| [`messages.csv`](20261001-104551-2692/messages.csv) | Message metadata, encoded sizes, and delivery outcomes |
| `actor-N-events.csv` | Per-actor message acceptance and rejection events |
| `actor-N-timing.csv` | Per-actor operation timings |
| `actor-N-summary.json` | Meter-process CPU usage, peak memory, and rejection counts |
| [`actors.csv`](20261001-104551-2692/actors.csv) | Actor-to-process mapping; actor 0 is the ESP |
| [`public_parameters.txt`](20261001-104551-2692/public_parameters.txt) | Cryptographic group parameters, public keys, and run identifier |
| [`checkpoint.json`](20261001-104551-2692/checkpoint.json) | Final completed-round counters |

Energy values are recorded in **mWh**, and customer bills in **nanoCAD**. Divide bill values by `1,000,000,000` to convert them to CAD. Round processing times exclude deliberate pacing waits. Communication measurements count serialized protocol traffic between distinct actors over local Unix-domain sockets.

To regenerate the readable summary, run this command from the repository root:

```bash
python3 summarize.py runs/20261001-104551-2692
```

Keep this archived directory intact when running additional experiments. New executions create separate output directories under `runs/`.
