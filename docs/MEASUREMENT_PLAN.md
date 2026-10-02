# Measurement plan for the actual Raspberry Pi

## Before the first reported run

1. Compile on the Pi with the supplied Makefile. Run `make test` and a small smoke test.
2. Record the hardware in environment.txt: actual Pi model, OS, GCC, GMP, OpenSSL.
3. Keep power and cooling consistent; avoid other heavy tasks during measurement.
4. Choose N, c, k, billing-rounds, total rounds, historical interval and tariff schedule
   before collecting the comparison runs. Save full config and all outputs.
5. Run a warm-up separately and retain it as a warm-up, not silently mixed into measured
   repetitions. Perform at least three repeat runs if available time permits; report
   their variability and number of repetitions, not invented significance.

`vcgencmd get_throttled` before and after the experiment can record throttling flags
if that utility is available. The simulator records startup temperature when Linux
exposes it; it does not continuously sample CPU frequency or temperature.

## Small validation, then main experiment

```bash
./meter-sim --meters 4 --committee 3 --threshold 2 --rounds 6 --billing-rounds 3
./meter-sim --meters 20 --committee 10 --threshold 6 --rounds 144 --billing-rounds 12
```

Use the settings your paper actually specifies. A one-hour experimental billing
period (12 five-minute readings) demonstrates several committee-selection events;
it must not be called a calendar-month billing workload. One 144-reading period
uses `--billing-rounds 144`; it gives only one selection event and cannot measure
long-run fairness.

A loop for three separate experiments, after a warm-up:

```bash
for repeat in 1 2 3; do
  ./meter-sim --meters 20 --committee 10 --threshold 6 --rounds 144 --billing-rounds 12
done
```

Default run directories are unique. Do not reuse an existing --out path: the program
refuses to overwrite results. If time is tight, one genuine measured run with its
limits stated is better than presenting projections as multiple measurements.

## Interpret the metrics correctly

- **Round processing wall time** starts before selection (when due) and ends after
  spatial reconstruction and any billing closure. It includes scheduling, socket
  waits and logging. Deliberate --interval sleep is excluded. Thus boundary rounds
  naturally cost more; do not compare them to a phase-only crypto benchmark.
- **Elapsed run time** includes controlled waiting, run finalization and shutdown.
  Parent startup/derivation is separately recorded. Child key derivation can finish
  during the first RPC wait, so the first round can contain startup wait.
- **Process CPU time** is consumed CPU, not elapsed time. Parent and children are
  reported separately. Summing child CPU is valid for aggregate CPU consumption;
  summing wall durations is not a makespan or concurrent throughput measure.
- **Per-command timings** use CLOCK_MONOTONIC and CLOCK_PROCESS_CPUTIME_ID. The current
  implementation reports grouped phases (e.g. reading commitment+share generation+
  encryption), not the exact timing boundaries in Chandra's tables. Reconstruct/verify
  times are separately available in ESP timing.csv and metrics.json. Never relabel
  these grouped timings as isolated exponentiation times.
- **Memory** uses Linux getrusage peak RSS, in KiB. Parent RSS and largest child's
  RSS are not total simultaneous resident memory. Per-meter summary files expose
  individual peaks; adding peaks can double-count shared pages and different times.
  Do not label the sum as exact total physical memory consumption.
- **Remote protocol bytes/messages** count each sender-to-distinct-recipient encoded
  message once, including 32-byte header + ciphertext + 16-byte tag. Broadcast is
  expanded into per-recipient unicasts. Replayed packets count again. A dropped
  simulated packet counts as sent. Self-deliveries are separately counted.
- **Harness IPC bytes** include request/reply frame headers and carriage of packet
  buffers. They are NOT an additional application payload metric to sum with protocol
  bytes; they overlap protocol carriage. Key provisioning, OS overhead, physical
  networking, ACKs at other layers and log-file sizes are excluded from protocol bytes.
- **Committee counts** are descriptive: B independent selection events of size c
  imply a nominal expected B*c/N selections per meter under a uniform model. A few
  billing periods cannot support broad fairness claims. Selection events can repeat
  membership and do not necessarily equal membership-change counts.

## Paper table suggestions

1. Setup: actual Pi4 model/RAM, OS, library/compiler versions, N/c/k, group bits,
   interval, billing-rounds, total rounds, tariff schedule, run repetitions.
2. Time: mean/median/max round wall time; spatial reconstruction and billing
   reconstruction distributions; boundary-vs-interior rounds if useful; CPU totals.
3. Memory: ESP parent peak RSS and distribution of per-meter peak RSS with precise
   definition; no unexplained total-memory claims.
4. Communication: total messages, serialized bytes, mean message bytes; optional
   separate selection, reading/share and reporting phases from messages.csv.
5. Correctness/attacks: output count, commitment and coverage status, oracle matches,
   rejection of tamper/replay, and exact injected attack model.

There is no honest numerical comparison to the published Pi5/512-bit timings without
matching hardware, group, software and instrumentation boundaries. You may explain
the differences and report a new implementation. No Raspberry Pi timings are supplied
with this package because it was built and tested on a separate Linux host.

## Preserve and retrieve your runs

On the Pi, from the project directory after a completed run:

```bash
python3 summarize.py runs/YOUR_RUN
python3 -m zipfile -c experiment-results.zip runs
```

From Windows PowerShell, copy the archive using the actual path on your Pi:

```powershell
& "$env:WINDIR\System32\OpenSSH\scp.exe" umair@192.168.137.189:~/pi-meter-sim/experiment-results.zip .
```

The IP can change when reconnecting. `hostname -I` on the Pi shows its addresses.
The Windows scp path is given explicitly because SSH was not on your PowerShell PATH.
