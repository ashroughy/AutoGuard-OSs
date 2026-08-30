#!/usr/bin/env python3
"""
AutoGuard OS
============
Real-data automotive CAN security monitoring system that demonstrates
core Operating System concepts (process management, multiprocessing,
processor scheduling, memory management, synchronization, and deadlock
detection/recovery) while analyzing a REAL labeled CAN-bus intrusion
dataset (HCRL "Car-Hacking Dataset").

This is not a simulator: the automotive data is real, and every OS
mechanism used here (processes, PIDs, OS scheduling priority / nice
values, threads, locks, measured CPU/RAM) is real -- backed by the
`multiprocessing`, `threading`, and `psutil` standard/third-party
libraries acting on the actual host OS.

Run:
    python3 autoguard.py
    python3 autoguard.py --data ../data/Car_Hacking_5pct.csv --sample 150000

Author: AutoGuard OS project (CSE323 - Operating Systems)
"""

import os
import sys
import time
import json
import random
import argparse
import threading
import multiprocessing as mp
from datetime import datetime

import numpy as np
import pandas as pd
import psutil

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# --------------------------------------------------------------------------- #
# Paths / configuration
# --------------------------------------------------------------------------- #
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SRC_DIR)
DEFAULT_DATA_PATH = os.path.join(PROJECT_ROOT, "data", "Car_Hacking_5pct.csv")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
REPORT_DIR = os.path.join(PROJECT_ROOT, "report")

ATTACK_LABELS = {"DoS", "Fuzzy", "gear", "RPM"}
NORMAL_LABEL = "R"


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def now_ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log_event(shared_log, lock, source, level, message):
    """Multiple OS processes append to ONE shared log under mutual exclusion.

    This is the real synchronization primitive (multiprocessing.Lock)
    protecting a real shared resource (a Manager list) written to by
    several concurrent OS processes.
    """
    entry = f"[{now_ts()}] [{level:7s}] [{source:16s}] {message}"
    with lock:
        shared_log.append(entry)
    print(entry, flush=True)


def mb(bytes_val):
    return bytes_val / (1024 * 1024)


# --------------------------------------------------------------------------- #
# SECTION 1 -- Real data loading
# --------------------------------------------------------------------------- #
def load_dataset(path, sample=None, seed=42):
    """Load the real HCRL Car-Hacking dataset (5% labeled subset).

    Columns present in this CSV: CAN ID, DATA[0..7], Label
    Label values: 'R' (normal / regular) or one of DoS / Fuzzy / gear / RPM
    (the four real injected-attack classes documented by HCRL).

    NOTE ON HONESTY: this particular pre-processed CSV (sourced from a
    public GitHub mirror of the dataset, prepared for image-based ML
    pipelines) does not retain the original per-message Timestamp / DLC
    columns present in the raw HCRL capture. All CAN IDs, byte payloads,
    and attack labels are the untouched, real, non-fabricated values from
    the original vehicle capture. Because there is no timestamp column,
    message order in the file (which preserves the original bus capture
    order) is used as the sequence axis for frequency/inter-arrival style
    statistics instead of wall-clock deltas.
    """
    df = pd.read_csv(path)
    if sample is not None and sample < len(df):
        df = df.sample(n=sample, random_state=seed).reset_index(drop=True)
    else:
        df = df.reset_index(drop=True)
    df["is_attack"] = df["Label"] != NORMAL_LABEL
    df["seq"] = np.arange(len(df))
    return df


def load_dataset_chunked(path, chunksize):
    """Generator that yields real CAN data in chunks (for memory demo)."""
    for chunk in pd.read_csv(path, chunksize=chunksize):
        chunk["is_attack"] = chunk["Label"] != NORMAL_LABEL
        yield chunk


# --------------------------------------------------------------------------- #
# SECTION 2 -- OS Concept 1 & 2: Process Management + Multiprocessing
#              (the four real analysis processes)
# --------------------------------------------------------------------------- #
def can_analyzer_proc(records, shared_log, log_lock, results, status):
    """Process 1: CAN Data Analyzer -- real process, real PID."""
    pid = os.getpid()
    status[pid] = {"name": "CAN Analyzer", "status": "RUNNING", "priority": "HIGH"}
    log_event(shared_log, log_lock, "CAN Analyzer", "INFO", f"Started (PID {pid})")

    t0 = time.time()
    df = pd.DataFrame.from_records(records)
    total = len(df)
    unique_ids = int(df["CAN ID"].nunique())
    id_counts = df["CAN ID"].value_counts().head(10)
    inter_arrival = None
    if total > 1:
        # message-order based spacing (no raw timestamp column in this subset)
        inter_arrival = float(np.mean(np.diff(df["seq"].values))) if "seq" in df else 1.0
    elapsed = time.time() - t0

    proc_handle = psutil.Process(pid)
    cpu_pct = proc_handle.cpu_percent(interval=0.2)
    rss_mb = mb(proc_handle.memory_info().rss)

    results["can_analyzer"] = {
        "pid": pid,
        "total_messages": total,
        "unique_can_ids": unique_ids,
        "top_can_ids": {str(k): int(v) for k, v in id_counts.items()},
        "avg_seq_spacing": inter_arrival,
        "elapsed_sec": elapsed,
        "cpu_percent": cpu_pct,
        "memory_mb": rss_mb,
    }
    status[pid] = {**status[pid], "status": "TERMINATED"}
    log_event(shared_log, log_lock, "CAN Analyzer", "INFO",
              f"Finished: {total} messages, {unique_ids} unique CAN IDs "
              f"in {elapsed:.3f}s")


def attack_detector_proc(records, shared_log, log_lock, results, status, threat_flag):
    """Process 2: Attack Detector -- real process, real PID.

    Demonstrates security-aware scheduling: if the measured attack ratio
    is HIGH, this process raises its OWN real OS scheduling priority via
    os/psutil `nice()` -- an actual kernel-level scheduling hint, not a
    simulated one.
    """
    pid = os.getpid()
    status[pid] = {"name": "Attack Detector", "status": "RUNNING", "priority": "HIGH"}
    log_event(shared_log, log_lock, "Attack Detector", "INFO", f"Started (PID {pid})")

    t0 = time.time()
    df = pd.DataFrame.from_records(records)
    total = len(df)
    label_counts = df["Label"].value_counts().to_dict()
    normal = int(label_counts.get(NORMAL_LABEL, 0))
    attacks = total - normal
    attack_ratio = attacks / total if total else 0.0

    if attack_ratio > 0.05:
        threat = "HIGH"
    elif attack_ratio > 0.01:
        threat = "MEDIUM"
    else:
        threat = "LOW"
    threat_flag.value = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}[threat]

    nice_before = psutil.Process(pid).nice()
    nice_after = nice_before
    if threat == "HIGH":
        try:
            p = psutil.Process(pid)
            p.nice(-10)  # real, kernel-level priority boost (requires privilege)
            nice_after = p.nice()
            log_event(shared_log, log_lock, "Attack Detector", "WARNING",
                      f"HIGH threat -> real OS priority raised "
                      f"(nice {nice_before} -> {nice_after})")
        except (psutil.AccessDenied, PermissionError) as e:
            log_event(shared_log, log_lock, "Attack Detector", "WARNING",
                      f"HIGH threat, but could not raise OS priority "
                      f"(insufficient privilege): {e}")

    elapsed = time.time() - t0
    proc_handle = psutil.Process(pid)
    cpu_pct = proc_handle.cpu_percent(interval=0.2)
    rss_mb = mb(proc_handle.memory_info().rss)

    results["attack_detector"] = {
        "pid": pid,
        "total_messages": total,
        "normal_messages": normal,
        "attack_messages": attacks,
        "attack_ratio": attack_ratio,
        "threat_level": threat,
        "attack_breakdown": {k: int(v) for k, v in label_counts.items() if k != NORMAL_LABEL},
        "nice_before": nice_before,
        "nice_after": nice_after,
        "elapsed_sec": elapsed,
        "cpu_percent": cpu_pct,
        "memory_mb": rss_mb,
    }
    status[pid] = {**status[pid], "status": "TERMINATED"}
    log_event(shared_log, log_lock, "Attack Detector", "INFO",
              f"Finished: {attacks}/{total} attack messages "
              f"({attack_ratio*100:.2f}%) -> threat level {threat}")


def resource_monitor_proc(shared_log, log_lock, samples, stop_event, status, interval=0.4):
    """Process 3: Resource Monitor -- samples REAL system CPU/RAM via psutil."""
    pid = os.getpid()
    status[pid] = {"name": "Resource Monitor", "status": "RUNNING", "priority": "MEDIUM"}
    log_event(shared_log, log_lock, "Resource Monitor", "INFO", f"Started (PID {pid})")

    while not stop_event.is_set():
        cpu = psutil.cpu_percent(interval=interval)
        vm = psutil.virtual_memory()
        samples.append({
            "t": time.time(),
            "cpu_percent": cpu,
            "mem_percent": vm.percent,
            "mem_used_mb": mb(vm.used),
        })

    status[pid] = {**status[pid], "status": "TERMINATED"}
    log_event(shared_log, log_lock, "Resource Monitor", "INFO",
              f"Finished: {len(samples)} samples collected")


def logger_proc(shared_log, log_lock, stop_event, status, heartbeat=0.6):
    """Process 4: Event Logger -- another real process writing into the
    SAME shared, lock-protected log used by every other process."""
    pid = os.getpid()
    status[pid] = {"name": "Event Logger", "status": "RUNNING", "priority": "MEDIUM"}
    log_event(shared_log, log_lock, "Event Logger", "INFO", f"Started (PID {pid})")

    beats = 0
    while not stop_event.is_set():
        time.sleep(heartbeat)
        beats += 1
        log_event(shared_log, log_lock, "Event Logger", "INFO",
                  f"heartbeat #{beats} - log size = {len(shared_log)}")

    status[pid] = {**status[pid], "status": "TERMINATED"}
    log_event(shared_log, log_lock, "Event Logger", "INFO", "Finished")


# --------------------------------------------------------------------------- #
# SECTION 3 -- OS Concept 5: Synchronization / Mutual exclusion micro-experiment
# --------------------------------------------------------------------------- #
def _increment_worker_unsafe(counter, n):
    for _ in range(n):
        val = counter.value
        time.sleep(0.0000005)  # widen the race window
        counter.value = val + 1


def _increment_worker_safe(counter, n, lock):
    for _ in range(n):
        with lock:
            val = counter.value
            time.sleep(0.0000005)
            counter.value = val + 1


def synchronization_experiment(n_workers=4, n_incr=2000):
    """Classic, quantitative mutual-exclusion demonstration:
    the SAME increment workload run without a Lock (race condition,
    real corrupted counter) and with a Lock (real, provably-correct
    counter) using real OS processes.
    """
    expected = n_workers * n_incr

    counter_unsafe = mp.Value("i", 0)
    procs = [mp.Process(target=_increment_worker_unsafe, args=(counter_unsafe, n_incr))
             for _ in range(n_workers)]
    for p in procs: p.start()
    for p in procs: p.join()
    unsafe_result = counter_unsafe.value

    counter_safe = mp.Value("i", 0)
    lock = mp.Lock()
    procs = [mp.Process(target=_increment_worker_safe, args=(counter_safe, n_incr, lock))
             for _ in range(n_workers)]
    for p in procs: p.start()
    for p in procs: p.join()
    safe_result = counter_safe.value

    return {
        "workers": n_workers,
        "increments_per_worker": n_incr,
        "expected_total": expected,
        "unsafe_result_no_lock": unsafe_result,
        "unsafe_lost_updates": expected - unsafe_result,
        "safe_result_with_lock": safe_result,
        "safe_correct": safe_result == expected,
    }


# --------------------------------------------------------------------------- #
# SECTION 4 -- OS Concept 6: Deadlock detection & recovery (real threads,
#              real locks, real circular-wait, bounded-wait detection)
# --------------------------------------------------------------------------- #
def deadlock_experiment(events):
    """Phase 1 deliberately creates a real circular-wait deadlock between two
    threads over two real threading.Lock resources, detects it via bounded
    waiting (acquire timeout), then Phase 2 recovers using a standard
    deadlock-*prevention* technique (global lock ordering) to show the
    same workload complete safely.
    """
    resource_A = threading.Lock()
    resource_B = threading.Lock()
    state = {"A": "IDLE", "B": "IDLE"}
    outcome = {"phase1_deadlock_detected": False, "phase1": {}, "phase2": {}}

    def log(msg):
        events.append(f"[{now_ts()}] {msg}")
        print(f"[{now_ts()}] {msg}", flush=True)

    # ---------- Phase 1: unsafe (inconsistent) lock ordering -> deadlock ----------
    def worker_A_unsafe():
        with resource_A:
            state["A"] = "HOLDING A, WAITING FOR B"
            log("Process A: holding Resource A, requesting Resource B")
            time.sleep(0.6)
            got = resource_B.acquire(timeout=2.0)
            if got:
                state["A"] = "HOLDING A and B"
                resource_B.release()
                outcome["phase1"]["A_timed_out"] = False
            else:
                outcome["phase1"]["A_timed_out"] = True
                log("Process A: TIMEOUT waiting for Resource B")

    def worker_B_unsafe():
        with resource_B:
            state["B"] = "HOLDING B, WAITING FOR A"
            log("Process B: holding Resource B, requesting Resource A")
            time.sleep(0.6)
            got = resource_A.acquire(timeout=2.0)
            if got:
                state["B"] = "HOLDING B and A"
                resource_A.release()
                outcome["phase1"]["B_timed_out"] = False
            else:
                outcome["phase1"]["B_timed_out"] = True
                log("Process B: TIMEOUT waiting for Resource A")

    t1 = threading.Thread(target=worker_A_unsafe)
    t2 = threading.Thread(target=worker_B_unsafe)
    t0 = time.time()
    t1.start(); t2.start()
    t1.join(); t2.join()
    outcome["phase1"]["wall_time_sec"] = time.time() - t0

    if outcome["phase1"].get("A_timed_out") and outcome["phase1"].get("B_timed_out"):
        outcome["phase1_deadlock_detected"] = True
        log("*** DEADLOCK DETECTED *** (circular wait: A->B and B->A, "
            "both bounded-waits expired)")
    else:
        log("No deadlock this run (timing did not align) -- see phase1 detail")

    # ---------- Phase 2: recovery via global lock ordering ----------
    log("Recovery initiated: applying global resource-ordering policy "
        "(always acquire Resource A before Resource B)")

    def worker_ordered(name, sleep_s):
        t0 = time.time()
        with resource_A:
            time.sleep(sleep_s)
            with resource_B:
                pass
        return time.time() - t0

    results = {}
    threads = []

    def run_and_store(name, sleep_s):
        results[name] = worker_ordered(name, sleep_s)

    t3 = threading.Thread(target=run_and_store, args=("P1", 0.05))
    t4 = threading.Thread(target=run_and_store, args=("P2", 0.05))
    t0 = time.time()
    t3.start(); t4.start()
    t3.join(); t4.join()
    outcome["phase2"] = {
        "wall_time_sec": time.time() - t0,
        "both_completed": len(results) == 2,
        "policy": "acquire Resource A before Resource B (consistent global order)",
    }
    log(f"Recovery result: both processes completed safely in "
        f"{outcome['phase2']['wall_time_sec']:.3f}s -- deadlock resolved")

    return outcome


# --------------------------------------------------------------------------- #
# SECTION 5 -- OS Concept 4: Memory management (real RSS measurements)
# --------------------------------------------------------------------------- #
def memory_experiment(path):
    """Compare REAL measured memory footprint of Method A (load entire
    CSV into RAM) vs Method B (chunked streaming processing)."""
    proc = psutil.Process(os.getpid())

    # ---- Method A: full load ----
    before_a = mb(proc.memory_info().rss)
    t0 = time.time()
    df_full = pd.read_csv(path)
    _ = df_full["Label"].value_counts()
    during_a = mb(proc.memory_info().rss)
    elapsed_a = time.time() - t0
    del df_full
    after_a = mb(proc.memory_info().rss)

    # ---- Method B: chunked ----
    before_b = mb(proc.memory_info().rss)
    t0 = time.time()
    peak_b = before_b
    total_rows = 0
    label_totals = {}
    for chunk in pd.read_csv(path, chunksize=20000):
        total_rows += len(chunk)
        vc = chunk["Label"].value_counts()
        for k, v in vc.items():
            label_totals[k] = label_totals.get(k, 0) + int(v)
        cur = mb(proc.memory_info().rss)
        peak_b = max(peak_b, cur)
    elapsed_b = time.time() - t0
    after_b = mb(proc.memory_info().rss)

    return {
        "method_a_full_load": {
            "before_mb": before_a, "during_mb": during_a, "after_mb": after_a,
            "elapsed_sec": elapsed_a,
        },
        "method_b_chunked": {
            "before_mb": before_b, "peak_mb": peak_b, "after_mb": after_b,
            "elapsed_sec": elapsed_b, "total_rows": total_rows,
        },
    }


# --------------------------------------------------------------------------- #
# SECTION 6 -- OS Concept 2 & 3: Multiprocessing vs sequential timing,
#              plus the full 4-process concurrent run
# --------------------------------------------------------------------------- #
def sequential_baseline(records_a, records_b):
    t0 = time.time()
    df1 = pd.DataFrame.from_records(records_a)
    _ = (df1["CAN ID"].nunique(), df1["CAN ID"].value_counts().head(10))
    df2 = pd.DataFrame.from_records(records_b)
    _ = df2["Label"].value_counts()
    return time.time() - t0


def run_concurrent_pipeline(df, results_dir):
    """Runs the four real OS processes concurrently and returns all
    measurements + the shared, lock-protected event log."""
    manager = mp.Manager()
    shared_log = manager.list()
    status = manager.dict()
    results = manager.dict()
    samples = manager.list()
    log_lock = mp.Lock()
    stop_event = mp.Event()
    threat_flag = manager.Value("i", 0)

    half = len(df) // 2
    records_a = df.iloc[:half].to_dict("records")
    records_b = df.iloc[half:].to_dict("records")

    # --- sequential baseline for comparison ---
    seq_time = sequential_baseline(records_a, records_b)

    p_analyzer = mp.Process(target=can_analyzer_proc,
                             args=(records_a, shared_log, log_lock, results, status))
    p_detector = mp.Process(target=attack_detector_proc,
                             args=(records_b, shared_log, log_lock, results, status, threat_flag))
    p_monitor = mp.Process(target=resource_monitor_proc,
                            args=(shared_log, log_lock, samples, stop_event, status))
    p_logger = mp.Process(target=logger_proc,
                           args=(shared_log, log_lock, stop_event, status))

    t0 = time.time()
    p_monitor.start()
    p_logger.start()
    p_analyzer.start()
    p_detector.start()

    p_analyzer.join()
    p_detector.join()

    stop_event.set()
    p_monitor.join(timeout=3)
    p_logger.join(timeout=3)
    concurrent_time = time.time() - t0

    return {
        "results": dict(results),
        "status": dict(status),
        "shared_log": list(shared_log),
        "resource_samples": list(samples),
        "sequential_time_sec": seq_time,
        "concurrent_time_sec": concurrent_time,
        "speedup": (seq_time / concurrent_time) if concurrent_time > 0 else None,
        "threat_level_code": threat_flag.value,
    }


# --------------------------------------------------------------------------- #
# SECTION 7 -- Charts
# --------------------------------------------------------------------------- #
def make_charts(df, run_out, mem_out, sync_out, results_dir):
    os.makedirs(results_dir, exist_ok=True)

    # 1. CAN traffic analysis: top CAN IDs by message count
    plt.figure(figsize=(9, 5))
    top_ids = df["CAN ID"].value_counts().head(12)
    plt.bar([str(i) for i in top_ids.index], top_ids.values, color="#2563eb")
    plt.title("CAN Analysis: Top CAN IDs by Message Count (real HCRL Car-Hacking data)")
    plt.xlabel("CAN ID")
    plt.ylabel("Message Count")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, "can_analysis.png"), dpi=130)
    plt.close()

    # 2. Process resource usage over time (resource monitor samples)
    samples = run_out["resource_samples"]
    plt.figure(figsize=(9, 5))
    if samples:
        t0 = samples[0]["t"]
        xs = [s["t"] - t0 for s in samples]
        cpu = [s["cpu_percent"] for s in samples]
        memp = [s["mem_percent"] for s in samples]
        plt.plot(xs, cpu, label="CPU %", color="#dc2626", marker="o")
        plt.plot(xs, memp, label="Memory %", color="#16a34a", marker="s")
    plt.title("Process/Resource Monitor: Real CPU & Memory Usage During Analysis")
    plt.xlabel("Seconds since monitor start")
    plt.ylabel("Percent")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, "process_resources.png"), dpi=130)
    plt.close()

    # 3. Memory comparison: Method A (full load) vs Method B (chunked)
    plt.figure(figsize=(7, 5))
    labels = ["Full Load\n(before)", "Full Load\n(during)", "Full Load\n(after)",
              "Chunked\n(before)", "Chunked\n(peak)", "Chunked\n(after)"]
    values = [
        mem_out["method_a_full_load"]["before_mb"],
        mem_out["method_a_full_load"]["during_mb"],
        mem_out["method_a_full_load"]["after_mb"],
        mem_out["method_b_chunked"]["before_mb"],
        mem_out["method_b_chunked"]["peak_mb"],
        mem_out["method_b_chunked"]["after_mb"],
    ]
    colors = ["#93c5fd", "#2563eb", "#1e3a8a", "#bbf7d0", "#22c55e", "#166534"]
    plt.bar(labels, values, color=colors)
    plt.ylabel("Process RSS Memory (MB)")
    plt.title("Memory Management: Full Load vs Chunk Processing\n(real RSS measurements)")
    plt.xticks(rotation=20)
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, "memory_comparison.png"), dpi=130)
    plt.close()

    # 4. Attack distribution
    plt.figure(figsize=(7, 6))
    counts = df["Label"].value_counts()
    ordered = counts.reindex(["R", "DoS", "Fuzzy", "gear", "RPM"]).fillna(0)
    colors4 = ["#16a34a", "#dc2626", "#f97316", "#9333ea", "#0891b2"]
    plt.pie(ordered.values, labels=ordered.index, autopct="%1.1f%%", colors=colors4,
            startangle=90)
    plt.title("Attack Distribution: Real CAN Traffic Labels\n(HCRL Car-Hacking Dataset subset)")
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, "attack_distribution.png"), dpi=130)
    plt.close()


# --------------------------------------------------------------------------- #
# SECTION 8 -- Dashboard (console) + final report
# --------------------------------------------------------------------------- #
def print_dashboard(df, run_out, mem_out, sync_out, deadlock_out, sched_note):
    total_msgs = len(df)
    attacks = int(df["is_attack"].sum())
    normal = total_msgs - attacks
    threat_map = {0: "LOW", 1: "MEDIUM", 2: "HIGH"}
    threat = threat_map[run_out["threat_level_code"]]

    samples = run_out["resource_samples"]
    avg_cpu = np.mean([s["cpu_percent"] for s in samples]) if samples else 0.0
    avg_mem = np.mean([s["mem_percent"] for s in samples]) if samples else 0.0

    print("\n" + "=" * 72)
    print("AUTOGUARD OS -- FINAL DASHBOARD".center(72))
    print("=" * 72)

    print("\n-- System Status --")
    print(f"  CPU Usage (avg during run): {avg_cpu:6.1f}%")
    print(f"  Memory Usage (avg during run): {avg_mem:6.1f}%")
    print(f"  Processes launched: 4 (+2 sync/deadlock experiment groups)")
    print(f"  Threat Level: {threat}")

    print("\n-- Process Table --")
    print(f"  {'PID':<8}{'Process':<20}{'Priority':<10}{'Status':<12}")
    print("  " + "-" * 50)
    for pid, info in run_out["status"].items():
        print(f"  {pid:<8}{info['name']:<20}{info['priority']:<10}{info['status']:<12}")

    print("\n-- Security (real HCRL Car-Hacking data) --")
    print(f"  CAN Messages analyzed: {total_msgs:,}")
    print(f"  Normal:                {normal:,}")
    print(f"  Attack (suspicious):   {attacks:,}  ({attacks/total_msgs*100:.2f}%)")
    ab = run_out["results"]["attack_detector"]["attack_breakdown"]
    for k, v in ab.items():
        print(f"    - {k:<8}: {v:,}")
    print(f"  Threat Level: {threat}")

    print("\n-- Multiprocessing vs Sequential --")
    print(f"  Sequential time:  {run_out['sequential_time_sec']:.4f}s")
    print(f"  Concurrent time:  {run_out['concurrent_time_sec']:.4f}s")
    if run_out["speedup"]:
        print(f"  Speedup:          {run_out['speedup']:.2f}x")
    print(f"  Logical CPUs available: {psutil.cpu_count(logical=True)} "
          f"(on a 1-core host, concurrent processes take turns via OS scheduling "
          f"rather than running in true parallel, so wall-clock speedup is not "
          f"expected -- this is still real multiprocessing overhead/behavior, not simulated)")

    print("\n-- Processor Scheduling --")
    print(f"  {sched_note}")

    print("\n-- Memory Management (real RSS, MB) --")
    a = mem_out["method_a_full_load"]; b = mem_out["method_b_chunked"]
    print(f"  Full load  : before={a['before_mb']:.1f}  during={a['during_mb']:.1f}  "
          f"after={a['after_mb']:.1f}  time={a['elapsed_sec']:.3f}s")
    print(f"  Chunked    : before={b['before_mb']:.1f}  peak={b['peak_mb']:.1f}  "
          f"after={b['after_mb']:.1f}  time={b['elapsed_sec']:.3f}s")

    print("\n-- Synchronization / Mutual Exclusion --")
    print(f"  Expected total after {sync_out['workers']} workers x "
          f"{sync_out['increments_per_worker']} increments = {sync_out['expected_total']}")
    print(f"  WITHOUT lock -> {sync_out['unsafe_result_no_lock']} "
          f"(lost updates: {sync_out['unsafe_lost_updates']})")
    print(f"  WITH lock    -> {sync_out['safe_result_with_lock']} "
          f"(correct: {sync_out['safe_correct']})")

    print("\n-- Deadlock Detection & Recovery --")
    print(f"  Deadlock detected in phase 1: {deadlock_out['phase1_deadlock_detected']}")
    print(f"  Recovery policy: {deadlock_out['phase2']['policy']}")
    print(f"  Both processes completed after recovery: "
          f"{deadlock_out['phase2']['both_completed']} "
          f"in {deadlock_out['phase2']['wall_time_sec']:.3f}s")

    print("\n-- OS Events (tail) --")
    for line in run_out["shared_log"][-10:]:
        print("  " + line)
    print("=" * 72 + "\n")


def write_report(df, run_out, mem_out, sync_out, deadlock_out, sched_note, report_path):
    total_msgs = len(df)
    attacks = int(df["is_attack"].sum())
    threat_map = {0: "LOW", 1: "MEDIUM", 2: "HIGH"}
    threat = threat_map[run_out["threat_level_code"]]
    ab = run_out["results"]["attack_detector"]["attack_breakdown"]
    a = mem_out["method_a_full_load"]; b = mem_out["method_b_chunked"]

    lines = []
    lines.append("# AutoGuard OS -- Final Report\n")
    lines.append(f"_Generated {datetime.now().isoformat(timespec='seconds')}_\n")
    lines.append("## 1. Real Dataset\n")
    lines.append("Source: HCRL Car-Hacking Dataset (5% labeled subset, real vehicle "
                  "CAN traffic captured via OBD-II, real injected DoS / Fuzzy / gear / "
                  "RPM-spoofing attacks).\n")
    lines.append(f"- Total messages analyzed: **{total_msgs:,}**")
    lines.append(f"- Normal messages: **{total_msgs-attacks:,}**")
    lines.append(f"- Attack messages: **{attacks:,}** ({attacks/total_msgs*100:.2f}%)")
    for k, v in ab.items():
        lines.append(f"  - {k}: {v:,}")
    lines.append(f"- Threat level: **{threat}**\n")

    lines.append("## 2. Process Management\n")
    lines.append("| PID | Process | Priority | Final Status |")
    lines.append("|---|---|---|---|")
    for pid, info in run_out["status"].items():
        lines.append(f"| {pid} | {info['name']} | {info['priority']} | {info['status']} |")
    lines.append("")

    lines.append("## 3. Multiprocessing vs Sequential Execution\n")
    lines.append(f"- Sequential: **{run_out['sequential_time_sec']:.4f}s**")
    lines.append(f"- Concurrent (4 real OS processes): **{run_out['concurrent_time_sec']:.4f}s**")
    if run_out["speedup"]:
        lines.append(f"- Speedup: **{run_out['speedup']:.2f}x**")
    lines.append(f"- Logical CPUs available on this host: **{psutil.cpu_count(logical=True)}**. "
                  f"On a single-core host, concurrently-launched processes are "
                  f"time-sliced by the OS scheduler rather than executed in true "
                  f"hardware parallel, so wall-clock speedup is not expected even "
                  f"though the processes are real, independent OS processes.\n")

    lines.append("## 4. Processor Scheduling\n")
    lines.append(sched_note + "\n")

    lines.append("## 5. Memory Management (real measured RSS)\n")
    lines.append("| Method | Before (MB) | During/Peak (MB) | After (MB) | Time (s) |")
    lines.append("|---|---|---|---|---|")
    lines.append(f"| Full load | {a['before_mb']:.1f} | {a['during_mb']:.1f} | "
                  f"{a['after_mb']:.1f} | {a['elapsed_sec']:.3f} |")
    lines.append(f"| Chunked | {b['before_mb']:.1f} | {b['peak_mb']:.1f} | "
                  f"{b['after_mb']:.1f} | {b['elapsed_sec']:.3f} |")
    lines.append("")

    lines.append("## 6. Synchronization / Mutual Exclusion\n")
    lines.append(f"{sync_out['workers']} real OS processes x "
                  f"{sync_out['increments_per_worker']} increments each on a shared counter.\n")
    lines.append(f"- Expected total: **{sync_out['expected_total']}**")
    lines.append(f"- Without lock: **{sync_out['unsafe_result_no_lock']}** "
                  f"(lost updates: {sync_out['unsafe_lost_updates']})")
    lines.append(f"- With lock: **{sync_out['safe_result_with_lock']}** "
                  f"(correct: {sync_out['safe_correct']})\n")

    lines.append("## 7. Deadlock Detection and Recovery\n")
    lines.append(f"- Phase 1 (unsafe lock ordering) deadlock detected: "
                  f"**{deadlock_out['phase1_deadlock_detected']}**")
    lines.append(f"- Recovery policy: {deadlock_out['phase2']['policy']}")
    lines.append(f"- Phase 2 (recovered) both processes completed: "
                  f"**{deadlock_out['phase2']['both_completed']}** "
                  f"in {deadlock_out['phase2']['wall_time_sec']:.3f}s\n")

    lines.append("## 8. Charts\n")
    lines.append("See `results/can_analysis.png`, `results/process_resources.png`, "
                  "`results/memory_comparison.png`, `results/attack_distribution.png`.\n")

    lines.append("## 9. OS Event Log (sample)\n")
    lines.append("```")
    for line in run_out["shared_log"][-25:]:
        lines.append(line)
    lines.append("```")

    with open(report_path, "w") as f:
        f.write("\n".join(lines))


# --------------------------------------------------------------------------- #
# MAIN
# --------------------------------------------------------------------------- #
def main():
    parser = argparse.ArgumentParser(description="AutoGuard OS")
    parser.add_argument("--data", default=DEFAULT_DATA_PATH, help="Path to real CAN CSV dataset")
    parser.add_argument("--sample", type=int, default=120000,
                         help="Number of real CAN rows to sample for the live pipeline "
                              "(keeps the demo fast; use -1 for full dataset)")
    args = parser.parse_args()

    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)

    print("=" * 72)
    print("AUTOGUARD OS -- Real-Data Automotive Security Monitoring".center(72))
    print("=" * 72)

    print(f"\n[STEP 1] Loading real CAN dataset from: {args.data}")
    sample = None if args.sample == -1 else args.sample
    df = load_dataset(args.data, sample=sample)
    print(f"  Loaded {len(df):,} real CAN-bus messages "
          f"({int(df['is_attack'].sum()):,} labeled as attack traffic)")

    print("\n[STEP 2/3] Launching 4 concurrent OS processes "
          "(Process Management + Multiprocessing)...")
    run_out = run_concurrent_pipeline(df, RESULTS_DIR)

    print("\n[STEP 4] Processor scheduling check...")
    det = run_out["results"]["attack_detector"]
    sched_note = (
        f"Attack Detector & CAN Analyzer are scheduled as HIGH priority security "
        f"workloads. Measured attack ratio {det['attack_ratio']*100:.2f}% -> threat "
        f"level {det['threat_level']}. Real OS nice value for Attack Detector: "
        f"{det['nice_before']} -> {det['nice_after']} "
        f"({'raised' if det['nice_after'] < det['nice_before'] else 'unchanged'})."
    )
    print("  " + sched_note)

    print("\n[STEP 5] Memory management experiment (Full load vs Chunk processing)...")
    mem_out = memory_experiment(args.data)

    print("\n[STEP 6] Synchronization / mutual exclusion experiment...")
    sync_out = synchronization_experiment()

    print("\n[STEP 7] Deadlock detection & recovery experiment...")
    deadlock_events = []
    deadlock_out = deadlock_experiment(deadlock_events)

    print("\n[STEP 8] Generating charts...")
    make_charts(df, run_out, mem_out, sync_out, RESULTS_DIR)

    print_dashboard(df, run_out, mem_out, sync_out, deadlock_out, sched_note)

    report_path = os.path.join(REPORT_DIR, "report.md")
    write_report(df, run_out, mem_out, sync_out, deadlock_out, sched_note, report_path)

    # Persist raw metrics as JSON for reproducibility / grading
    metrics_path = os.path.join(RESULTS_DIR, "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump({
            "dataset_rows_analyzed": len(df),
            "attack_messages": int(df["is_attack"].sum()),
            "process_results": run_out["results"],
            "process_status": run_out["status"],
            "sequential_time_sec": run_out["sequential_time_sec"],
            "concurrent_time_sec": run_out["concurrent_time_sec"],
            "speedup": run_out["speedup"],
            "memory_experiment": mem_out,
            "synchronization_experiment": sync_out,
            "deadlock_experiment": deadlock_out,
        }, f, indent=2, default=str)

    print(f"Report written to: {report_path}")
    print(f"Metrics written to: {metrics_path}")
    print(f"Charts written to: {RESULTS_DIR}/*.png")


if __name__ == "__main__":
    mp.set_start_method("fork", force=True)
    main()
