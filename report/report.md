# AutoGuard OS -- Final Report

_Generated 2026-08-29T16:04:14_

## 1. Real Dataset

Source: HCRL Car-Hacking Dataset (5% labeled subset, real vehicle CAN traffic captured via OBD-II, real injected DoS / Fuzzy / gear / RPM-spoofing attacks).

- Total messages analyzed: **200,000**
- Normal messages: **171,351**
- Attack messages: **28,649** (14.32%)
  - RPM: 3,965
  - gear: 3,642
  - DoS: 3,541
  - Fuzzy: 3,022
- Threat level: **HIGH**

## 2. Process Management

| PID | Process | Priority | Final Status |
|---|---|---|---|
| 910 | Resource Monitor | MEDIUM | TERMINATED |
| 911 | Event Logger | MEDIUM | TERMINATED |
| 914 | CAN Analyzer | HIGH | TERMINATED |
| 922 | Attack Detector | HIGH | TERMINATED |

## 3. Multiprocessing vs Sequential Execution

- Sequential: **0.4798s**
- Concurrent (4 real OS processes): **1.2339s**
- Speedup: **0.39x**
- Logical CPUs available on this host: **1**. On a single-core host, concurrently-launched processes are time-sliced by the OS scheduler rather than executed in true hardware parallel, so wall-clock speedup is not expected even though the processes are real, independent OS processes.

## 4. Processor Scheduling

Attack Detector & CAN Analyzer are scheduled as HIGH priority security workloads. Measured attack ratio 14.17% -> threat level HIGH. Real OS nice value for Attack Detector: 0 -> -10 (raised).

## 5. Memory Management (real measured RSS)

| Method | Before (MB) | During/Peak (MB) | After (MB) | Time (s) |
|---|---|---|---|---|
| Full load | 241.5 | 347.3 | 232.2 | 0.468 |
| Chunked | 232.2 | 247.4 | 247.4 | 0.465 |

## 6. Synchronization / Mutual Exclusion

4 real OS processes x 2000 increments each on a shared counter.

- Expected total: **8000**
- Without lock: **2110** (lost updates: 5890)
- With lock: **8000** (correct: True)

## 7. Deadlock Detection and Recovery

- Phase 1 (unsafe lock ordering) deadlock detected: **True**
- Recovery policy: acquire Resource A before Resource B (consistent global order)
- Phase 2 (recovered) both processes completed: **True** in 0.101s

## 8. Charts

See `results/can_analysis.png`, `results/process_resources.png`, `results/memory_comparison.png`, `results/attack_distribution.png`.

## 9. OS Event Log (sample)

```
[16:04:08.608] [INFO   ] [Resource Monitor] Started (PID 910)
[16:04:08.610] [INFO   ] [Event Logger    ] Started (PID 911)
[16:04:08.612] [INFO   ] [CAN Analyzer    ] Started (PID 914)
[16:04:08.619] [INFO   ] [Attack Detector ] Started (PID 922)
[16:04:09.219] [INFO   ] [Event Logger    ] heartbeat #1 - log size = 4
[16:04:09.365] [WARNING] [Attack Detector ] HIGH threat -> real OS priority raised (nice 0 -> -10)
[16:04:09.553] [INFO   ] [CAN Analyzer    ] Finished: 100000 messages, 1596 unique CAN IDs in 0.736s
[16:04:09.566] [INFO   ] [Attack Detector ] Finished: 14170/100000 attack messages (14.17%) -> threat level HIGH
[16:04:09.816] [INFO   ] [Resource Monitor] Finished: 3 samples collected
[16:04:09.819] [INFO   ] [Event Logger    ] heartbeat #2 - log size = 9
[16:04:09.819] [INFO   ] [Event Logger    ] Finished
```