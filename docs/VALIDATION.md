# Validation record

This document records development checks and the completed Raspberry Pi
experiment. The build, arithmetic, integration, and representative-size checks
below were performed on the development Linux host. The hardware experiment
was completed on a Raspberry Pi 4, with its measurements and results preserved
in `runs/20261001-104551-2692/`.

## Build

C11, GCC, optimization -O2, -Wall -Wextra -Wpedantic -Werror: passed with no warnings.
GMP and OpenSSL were dynamically linked. The simulator was also built and
executed on the Raspberry Pi 4 for the experiment documented below.

## Cryptographic arithmetic checks

- Fixed p has 2048 bits; p and q passed GMP probable-prime checks.
- g and h belong to the order-q subgroup; h is reproduced independently with Python
  SHAKE256 and modular arithmetic.
- Reconstructed constant AND first coefficient for thresholds 2..10, five random
  polynomial trials each, using nonconsecutive coordinates.
- Pedersen addition and tariff-weighting identities passed.
- C(5,7) matched an independent Python modular-exponentiation result.
- Two endpoints derived identical directional X25519/HKDF keys.
- AES-GCM round trip passed; modified ciphertext and modified associated data failed.

## Integration checks

- Honest small run, including both a full period and a partial final period.
- Actual output values independently matched plaintext arithmetic.
- Committee selected exactly once per period in recorded schedules.
- Logged remote messages/bytes matched recomputed totals from messages.csv.
- Tampered ciphertext rejected, with incomplete affected state.
- Replayed ciphertext rejected, with no double-counting.
- Altered share and altered spatial report failed the affected aggregate checks.
- Dropped share left affected output incomplete.
- Known two-round CSV produced customer bills 500000,800000,1100000,1400000 nanoCAD.
- Data exhaustion finalized the partial period.
- Zero tariff produced valid zero bills.
- Ten-meter, 4-of-6 reconstruction passed.
- Ctrl+C delivered to the foreground process group stopped gracefully.
- q + Enter stopped gracefully.
- Interrupt during active 20-meter protocol traffic completed the current round and
  finalized all completed-prefix results correctly.
- Wall-clock duration limit stopped gracefully after a completed round.

## Representative-size check

N=20, c=10, k=6; six reporting rounds; three rounds per billing period:

- Six verified complete spatial totals.
- Forty verified complete customer bills (20 customers times two periods).
- No incomplete/rejected outputs in the honest run.
- Every accepted output matched the independent oracle.
- Two committee-selection events.
- 5600 remote protocol deliveries, independently consistent with the configured
  all-to-all selection/commitment dissemination and point-to-point shares/reports.

A separate AddressSanitizer + UndefinedBehaviorSanitizer build also completed a
small bad-share run without reported address/undefined-behavior errors. Leak checking
was disabled because long-lived actor state is reclaimed on process exit.

## Raspberry Pi experiment

The experiment completed on 1 October 2026 using a Raspberry Pi 4 Model B
Rev. 1.1 with 1 GB RAM and a 64-bit Linux operating system. The software
environment used GCC 14.2.0, GMP 6.3.0, and OpenSSL 3.5.7.

Twenty smart-meter processes and one ESP/coordinator process executed the
protocol for approximately 75 minutes. The committee contained ten meters,
with a reconstruction threshold of six. Each billing period contained ten
reporting rounds. Round starts were scheduled 30 seconds apart, and each
synthetic reading represented five minutes of consumption.

### Completed outputs

- 150 reporting rounds.
- 15 complete billing periods and 15 committee-selection events.
- 150 verified spatial aggregates.
- 300 verified customer bills.
- All 450 outputs matched independent plaintext reference calculations.
- No partial, incomplete, or rejected outputs.
- No rejected protocol messages.

Committee membership remained fixed for the ten rounds within each billing
period. Selection was repeated at the next billing boundary after finalization
of the preceding period. New committees initialized fresh billing accumulators.

### Recorded measurements

| Measurement | Value |
|---|---|
| Wall-clock duration | 4500.048 s |
| Mean round processing time | 8.053 s |
| Median round processing time | 7.981 s |
| Maximum round processing time | 8.661 s |
| Protocol messages between distinct actors | 105,000 |
| Serialized protocol traffic | 29,250,000 bytes |
| Mean protocol message size | 278.57 bytes |
| Parent-process peak resident memory | 7448 KiB |
| Individual meter-process peak resident memory | 5332–5536 KiB |

Round processing times exclude deliberate waits between scheduled rounds.
Traffic measurements include serialized protocol headers, ciphertexts, and
authentication tags. Processes were scheduled sequentially on the single Pi
and communicated over local Unix-domain sockets.

The experiment used synthetic readings with seed 42 and repeating tariffs
of 98, 157, and 203 microCAD/Wh. It exercised normal operation with the
`none` fault scenario. The fault-injection checks listed earlier belong to
the development validation record.

### Experimental records

The complete run is preserved in [`runs/20261001-104551-2692/`](../runs/20261001-104551-2692/):

- `config.json` and `environment.txt` record the configuration and platform.
- `results.csv` records reconstructed outputs and reference comparisons.
- `metrics.json` and `rounds.csv` record aggregate and per-round measurements.
- `committees.csv` records committee membership for each billing period.
- `messages.csv` and the per-actor logs preserve message and processing records.
- `summary.txt` provides a readable summary of the run.

## Evaluation scope

The recorded hardware experiment evaluates aggregation, customer billing,
committee transitions, and resource usage in a multiprocess deployment on
one Raspberry Pi. Measurements across physical meter networks and repeated
hardware trials are further evaluation tasks.

The protocol assumptions and the linked share-and-commitment construction's
privacy limitation are documented in [PROTOCOL.md](PROTOCOL.md).
