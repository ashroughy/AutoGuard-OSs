# AutoGuard OS

**Real-Data Automotive Security Monitoring with OS Resource Management**

AutoGuard OS analyzes a real, labeled automotive CAN intrusion dataset
(HCRL Car-Hacking Dataset) while demonstrating core Operating Systems
concepts using **real Python OS processes, threads, locks, and measured
CPU/memory** — not a simulation.

Concepts demonstrated:

1. **Process Management** — 4 real OS processes (real PIDs, real states)
2. **Multiprocessing** — concurrent vs. sequential execution, timed
3. **Processor Scheduling** — security-aware priority policy using real OS `nice` values
4. **Memory Management** — real RSS measurements, full-load vs. chunked processing
5. **Synchronization / Mutual Exclusion** — real race condition vs. real `Lock`-protected counter
6. **Deadlock Detection & Recovery** — real circular-wait deadlock, timeout detection, ordered-lock recovery
7. **Automotive Network Security** — real CAN traffic / attack-type breakdown

## Quick start

```bash
pip install -r requirements.txt
cd src
python3 autoguard.py
```

Optional flags:

```bash
python3 autoguard.py --data ../data/Car_Hacking_5pct.csv --sample 120000
python3 autoguard.py --sample -1   # use the entire ~818k-row dataset
```

## Output

- Console dashboard (process table, security summary, scheduling,
  memory, synchronization, deadlock recovery, tail of the OS event log)
- `results/can_analysis.png` — top CAN IDs by message count
- `results/process_resources.png` — CPU/RAM sampled live during the run
- `results/memory_comparison.png` — full-load vs. chunked RSS memory
- `results/attack_distribution.png` — real attack-type breakdown
- `results/metrics.json` — every raw measurement, for grading/reproducibility
- `report/report.md` — full written report generated from the actual run

## Project layout

```
AutoGuard-OS/
├── README.md
├── requirements.txt
├── src/
│   └── autoguard.py
├── data/
│   ├── README.md
│   └── Car_Hacking_5pct.csv
├── results/
│   ├── can_analysis.png
│   ├── process_resources.png
│   ├── memory_comparison.png
│   └── attack_distribution.png
└── report/
    └── report.md
```

## Notes

- The 4 pipeline processes (CAN Analyzer, Attack Detector, Resource Monitor,
  Event Logger) are launched with `multiprocessing.Process` — each has a
  real OS PID, visible with `ps` while running.
- The Attack Detector raises its **actual OS scheduling priority** (`nice`)
  when it measures a HIGH threat level — a genuine kernel-level scheduling
  hint, applied via `psutil`/`os`.
- The synchronization experiment runs the identical increment workload with
  and without a `multiprocessing.Lock`, so the corrupted vs. correct counter
  values you see are real race-condition results, not scripted numbers.
- The deadlock experiment creates a genuine circular-wait between two real
  `threading.Lock` objects, detects it via bounded-wait timeout, then
  recovers using a global lock-ordering policy.
- If run on a single-core host, concurrent processes are time-sliced by the
  OS rather than executed in true hardware parallel, so multiprocessing
  wall-clock "speedup" may be below 1x — this is accurately reported rather
  than faked.
