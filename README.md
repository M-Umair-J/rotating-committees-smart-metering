# Billing Period Smart Metering

A C implementation of decentralized smart metering with billing-period aggregation committees, per-round spatial aggregation, and customer-specific Time-of-Use billing.

Each smart meter runs as a separate process. Meters select an aggregation committee at the start of a billing period through a commit–reveal procedure. Committee members accumulate reading shares throughout that period, and the Electrical Service Provider (ESP) reconstructs spatial totals after each reporting round and customer bills at billing closure. A new committee is selected for the next period, with fresh billing accumulators.

The simulator uses GMP for finite-field arithmetic and OpenSSL for cryptographic operations. It supports synthetic readings, CSV input, configurable execution schedules, fault scenarios, and detailed experiment logs.

## Protocol overview

1. **Committee selection:** meters commit to and reveal random contributions, then derive deterministic selection scores from the common seed.
2. **Reading submission:** each meter creates a Pedersen commitment and Shamir shares for its reading, sending shares to committee members through authenticated encrypted channels.
3. **Spatial aggregation:** committee members add shares across meters for the current reporting round. The ESP reconstructs and verifies the total.
4. **Customer billing:** committee members maintain a separate tariff-weighted accumulator for each customer. The ESP reconstructs and verifies customer bills at period closure.
5. **Period transition:** the completed period is finalized before the next committee starts with fresh state. No unfinished billing state is transferred.

Commitments use a 2048-bit prime modulus and a 2047-bit prime-order subgroup. Share arithmetic operates over the subgroup-order field. Pairwise channels use X25519, HKDF-SHA256, and AES-256-GCM.

## Requirements

- Linux, including Raspberry Pi OS
- A C11 compiler and `make`
- GMP development headers
- OpenSSL development headers
- Python 3 for the interactive launcher, result summaries, and integration tests

On Debian or Raspberry Pi OS:

```bash
sudo apt install -y build-essential libgmp-dev libssl-dev python3
```

## Build and quick start

From the repository directory:

```bash
make
```

Run a small experiment:

```bash
./meter-sim --meters 4 --committee 3 --threshold 2 \
  --rounds 6 --billing-rounds 3
```

This configuration produces six spatial totals and eight complete customer bills: four customers across two billing periods. The simulator prints the output directory when it starts and saves results there.

For the interactive menu:

```bash
python3 run.py
```

The menu provides a small test, a 20-meter example, and custom configuration. Build with `make` before launching the menu.

Run the included tests:

```bash
make test
```

The suite covers cryptographic arithmetic, aggregation and billing correctness, message tampering, replay, missing shares, and graceful stopping. Test output is separate from the archived experiment results.

## Configuration

| Option | Purpose | Default |
|---|---|---|
| `--meters` | Number of smart-meter processes | `20` |
| `--committee` | Committee size | `10` |
| `--threshold` | Shares required for reconstruction | `6` |
| `--rounds` | Maximum reporting rounds; `0` runs until another stop condition | `144` |
| `--billing-rounds` | Readings per billing period | `12` |
| `--interval` | Minimum wall-clock seconds between round starts | `0` |
| `--duration` | Wall-clock limit in seconds; `0` means no time limit | `0` |
| `--sample-seconds` | Consumption interval represented by each synthetic reading | `300` |
| `--tariffs` | Comma-separated tariff sequence in microCAD/Wh | `98,157,203` |
| `--seed` | Reproducible synthetic-reading seed | `42` |
| `--csv` | Input CSV path; otherwise use synthetic readings | None |
| `--attack` | Fault scenario | `none` |
| `--attack-round` | Zero-based round for fault injection | `2` |
| `--out` | New output directory | Automatically generated under `runs/` |

Use `./meter-sim --help` for the command-line reference. The threshold must satisfy `2 <= threshold <= committee <= meters`.

Reporting pace and represented consumption time are independent. For example, `--interval 30 --sample-seconds 300` starts rounds at least 30 seconds apart while each synthetic reading represents five minutes of consumption. If processing takes longer than the interval, the simulator does not skip rounds to catch up.

Tariffs repeat by reporting round. The values `98,157,203` microCAD/Wh correspond to 9.8, 15.7, and 20.3 cents/kWh. The repeating sequence exercises time-dependent billing; calendar-based tariff schedules can be supplied as an explicit sequence. The synthetic-reading seed does not control cryptographic randomness or guarantee identical committee selections across runs.

### Run until stopped

```bash
./meter-sim --rounds 0 --interval 30 --billing-rounds 10
```

### Run for approximately ten minutes

```bash
./meter-sim --rounds 0 --duration 600 --interval 30 \
  --billing-rounds 10
```

### Replay readings from CSV

```bash
./meter-sim --meters 4 --committee 3 --threshold 2 \
  --csv examples/readings.csv --rounds 0 \
  --billing-rounds 2 --tariffs 100,200
```

The CSV header must be `round,sm1,...,smN`, with sequential zero-based round numbers. Reading values are nonnegative integer **mWh of energy for the reporting interval**, not power in watts. Convert external datasets into this format before running the simulator. Missing, negative, or fractional readings are rejected. End of input triggers normal finalization.

## Stopping and finalization

Press **Ctrl+C**, or type **q** followed by **Enter**, to request a graceful stop. The simulator finishes the active round and saves its outputs and metrics. Wait for the completion message before closing the terminal or powering off the device.

Completed billing periods retain their full bills. An unfinished period can produce a verified partial subtotal when its checks pass; it is labelled separately from a complete bill. A duration limit may be exceeded by the time needed to finish the active round and finalize results.

Partial subtotals are an experimental stopping feature. The normal reporting schedule reconstructs customer bills only at billing-period closure. There is no automatic resume after a crash or power loss.

## Recorded Raspberry Pi experiment

The repository includes the experiment in [`runs/20261001-104551-2692/`](runs/20261001-104551-2692/).

| Setting | Recorded value |
|---|---|
| Hardware | Raspberry Pi 4 Model B Rev. 1.1, 1 GB RAM |
| Software | GCC 14.2.0, GMP 6.3.0, OpenSSL 3.5.7 |
| Meter processes | 20 |
| Committee size / threshold | 10 / 6 |
| Run duration | 4500.048 seconds, approximately 75 minutes |
| Reporting rounds | 150 |
| Reporting pace | 30 seconds between scheduled round starts |
| Consumption interval per reading | 300 seconds |
| Readings per billing period | 10 |
| Completed billing periods | 15 |
| Input | Synthetic readings, seed 42 |
| Tariffs | Repeating `98,157,203` microCAD/Wh |
| Fault scenario | `none` |

The recorded configuration can be run with:

```bash
./meter-sim --meters 20 --committee 10 --threshold 6 \
  --rounds 0 --duration 4500 --interval 30 \
  --billing-rounds 10 --sample-seconds 300 \
  --tariffs 98,157,203 --seed 42 --attack none
```

The run produced **150 spatial totals and 300 customer bills**, all matching independent plaintext reference calculations. Average round processing time was **8.053 seconds**, excluding deliberate pacing waits. Serialized protocol traffic totalled **29.25 MB** across **105,000 messages**, with an average message size of **278.57 bytes**. Individual meter processes reached peak resident memory usage between **5332 and 5536 KiB**.

These measurements come from separate processes on one Raspberry Pi, scheduled sequentially and communicating through local Unix-domain sockets. Message sizes include serialized protocol headers, ciphertexts, and authentication tags. Timing and committee membership will vary between executions; the archive preserves the actual observed run.

The interactive menu's 144-round preset is a separate usage example. Use the command above to reproduce the archived experiment's configuration.

## Results and logs

Summarize an output directory with:

```bash
python3 summarize.py runs/20261001-104551-2692
```

| File | Contents |
|---|---|
| `config.json` | Run configuration |
| `environment.txt` | Hardware, operating system, compiler, and library details |
| `metrics.json` | Timing, CPU usage, memory peaks, traffic, and output counts |
| `results.csv` | Spatial totals, customer bills, statuses, and reference comparisons |
| `rounds.csv` | Processing time and tariff for each round |
| `committees.csv` | Selected membership for each billing period |
| `messages.csv` | Message metadata, size, and delivery outcome |
| `actor-N-events.csv` | Per-actor message acceptance and rejection events |
| `actor-N-timing.csv` | Per-actor operation timings |
| `actor-N-summary.json` | Meter CPU usage, peak memory, and rejection count |
| `actors.csv` | Actor-to-process mapping; actor `0` is the ESP |
| `public_parameters.txt` | Group parameters, public keys, and run identifier |
| `checkpoint.json` | Latest completed-round counters |
| `summary.txt` | Human-readable output from the summary script |

Energy outputs are in **mWh**. Bill outputs are in **nanoCAD**; divide by `1,000,000,000` to obtain CAD. A verified status indicates that the configured commitment and coverage checks passed. Reference comparisons independently check the calculated output value.

## Fault scenarios

Choose one scenario per run using `--attack`, with its zero-based reporting round selected by `--attack-round`:

- `tamper`
- `replay`
- `bad-share`
- `bad-aggregate`
- `drop-share`
- `none`

For example:

```bash
./meter-sim --meters 4 --committee 3 --threshold 2 \
  --rounds 6 --billing-rounds 3 \
  --attack bad-share --attack-round 1
```

Inspect output statuses and actor logs to determine the effect of an injected fault. A detected protocol fault need not terminate the simulator with an error exit code. Injection points and expected behavior are described in [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Security model

The implementation is a research simulator with a trusted execution host and key-provisioning harness. It uses authenticated encrypted channels and aggregate commitment checks. The single-polynomial construction places the commitment blinding value in the first coefficient of the reading polynomial; joint access to commitments and sufficient shares permits candidate-reading tests. The security assumptions and this construction's limitations are documented in [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Project files

- [`src/`](src/) — C protocol and cryptographic implementation
- [`tests/`](tests/) — cryptographic and integration checks
- [`examples/`](examples/) — sample CSV readings
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — protocol, message handling, and security assumptions
- [`docs/MEASUREMENT_PLAN.md`](docs/MEASUREMENT_PLAN.md) — measurement definitions and experiment guidance
- [`docs/VALIDATION.md`](docs/VALIDATION.md) — development validation record
- [`runs/`](runs/) — archived experiment outputs
- `run.py` — interactive configuration
- `summarize.py` — result summaries
