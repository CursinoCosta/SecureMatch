"""
Resilient Benchmark Orchestrator for SecureMatch.

Features:
1. Granular Checkpointing:
   Persists progress to `benchmark/results/checkpoint.json` after every single test size.
   If interrupted or in case of errors, re-running automatically resumes exactly
   where it stopped without repeating completed work.
2. Scales up to 500,000 records:
   - Benchmark 1 (Scalability): N in [100, 1000, 10000, 50000, 100000, 500000]
   - Benchmark 3 (Asymmetric): |A| = 500 vs |B| in [1000, 10000, 50000, 100000, 500000]
3. Order of Execution (Quickest to Longest):
   - Step 1: Naive SHA-256 Preimage Cracking (CPF & CNPJ) (~1s)
   - Step 2: Benchmark 4 - Transport Channel Overhead (~10s)
   - Step 3: Benchmark 2 - Component Runtime Breakdown (~10s)
   - Step 4: Benchmark 5 - False Negative Rate vs Data Quality Decay (~30s)
   - Step 5: Benchmark 1 - Scalability & The Privacy Tax (Scales up to 500,000)
   - Step 6: Benchmark 3 - Asymmetric Scale Dilemma (Scales up to 500,000)
   - Step 7: (THE LONGEST - RUNS LAST) secp256k1 ECDLP Exhaustion Attack (3 Hours / 10,800s)
             with cumulative attempt checkpointing every 30s.
4. Automated Plot Generation:
   Compiles all final data into `metrics.json` and renders publication-ready figures.
"""

from __future__ import annotations
import argparse
import asyncio
import json
import math
import os
import signal
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.crypto.curve import (
    N,
    P,
    Point,
    generate_private_scalar,
    point_multiply,
    _jacobian_add,
)
from src.crypto.hash_to_curve import hash_to_curve
from src.data_pipeline.schema import create_cpf_schema
from src.protocol.party_client import PSIClient
from src.protocol.party_server import PSIServer
from src.transport.memory_channel import run_in_memory_psi
from src.transport.socket_transport import SocketPSIServer, run_socket_client
from benchmark.generate_synthetic import generate_valid_cpf_digits
from benchmark.baseline_naive import naive_sha256_psi
from benchmark.security_cracker import crack_naive_sha256_cpf, crack_naive_sha256_cnpj
from benchmark.run_benchmarks import (
    make_benchmark_pair,
    run_benchmark_component_breakdown,
    run_benchmark_channel_overhead,
    run_benchmark_data_decay,
)
from benchmark.plot_metrics import generate_all_plots


RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
CHECKPOINT_PATH = os.path.join(RESULTS_DIR, "checkpoint.json")
METRICS_PATH = os.path.join(RESULTS_DIR, "metrics.json")


class BenchmarkOrchestrator:
    """Manages resilient execution and state checkpointing across all benchmarks."""

    def __init__(
        self,
        checkpoint_path: str = CHECKPOINT_PATH,
        metrics_path: str = METRICS_PATH,
        exhaustion_duration_seconds: float = 10800.0,
        quick_mode: bool = False,
    ) -> None:
        self.checkpoint_path = checkpoint_path
        self.metrics_path = metrics_path
        self.exhaustion_duration_seconds = exhaustion_duration_seconds
        self.quick_mode = quick_mode
        self.state: Dict[str, Any] = self._load_checkpoint()

    def _load_checkpoint(self) -> Dict[str, Any]:
        if os.path.exists(self.checkpoint_path):
            try:
                with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    print(f"🔄 Loaded existing checkpoint from: {self.checkpoint_path}")
                    return data
            except Exception as e:
                print(f"⚠️  Failed to read checkpoint ({e}), starting fresh.")

        return {
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "quick_mode": self.quick_mode,
            "stages": {},
        }

    def save_checkpoint(self) -> None:
        self.state["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        os.makedirs(os.path.dirname(os.path.abspath(self.checkpoint_path)), exist_ok=True)
        temp_path = f"{self.checkpoint_path}.tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(self.state, f, indent=2)
        os.replace(temp_path, self.checkpoint_path)

    def is_stage_completed(self, stage_name: str) -> bool:
        stage = self.state.get("stages", {}).get(stage_name, {})
        return stage.get("status") == "completed"

    def record_stage_result(self, stage_name: str, result_data: Any) -> None:
        self.state.setdefault("stages", {})[stage_name] = {
            "status": "completed",
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "result": result_data,
        }
        self.save_checkpoint()

    # -----------------------------------------------------------------------
    # STAGE 1: NAIVE SHA-256 PREIMAGE CRACKERS (~1s)
    # -----------------------------------------------------------------------
    def run_stage_1_sha_crackers(self) -> None:
        if self.is_stage_completed("stage_1_sha_crackers"):
            print("\n⏩ [Stage 1/7] SHA-256 Preimage Crackers already COMPLETED.")
            return

        print("\n" + "=" * 75)
        print("⚡ [Stage 1/7] Running Naive SHA-256 Preimage Crackers (CPF & CNPJ)...")
        print("=" * 75)

        import hashlib
        target_cpf = "12345678909"
        hash_cpf = hashlib.sha256(target_cpf.encode("utf-8")).hexdigest()
        cpf_res = crack_naive_sha256_cpf(hash_cpf, cpf_prefix_hint="1234")

        target_cnpj = "12345678000195"
        hash_cnpj = hashlib.sha256(target_cnpj.encode("utf-8")).hexdigest()
        cnpj_res = crack_naive_sha256_cnpj(hash_cnpj, branch="0001", cnpj_prefix_hint="12345")

        combined = {
            "cpf_crack": cpf_res,
            "cnpj_crack": cnpj_res,
        }
        print(f"   ✅ CPF Cracked:  {cpf_res['cracked_plaintext']} in {cpf_res['elapsed_seconds']:.3f}s ({cpf_res['attempts']:,} attempts)")
        print(f"   ✅ CNPJ Cracked: {cnpj_res['cracked_plaintext']} in {cnpj_res['elapsed_seconds']:.3f}s ({cnpj_res['attempts']:,} attempts)")

        self.record_stage_result("stage_1_sha_crackers", combined)

    # -----------------------------------------------------------------------
    # STAGE 2: BENCHMARK 4 - TRANSPORT CHANNEL OVERHEAD (~10s)
    # -----------------------------------------------------------------------
    def run_stage_2_channel_overhead(self) -> None:
        if self.is_stage_completed("stage_2_channel_overhead"):
            print("\n⏩ [Stage 2/7] Benchmark 4 (Transport Channel Overhead) already COMPLETED.")
            return

        print("\n" + "=" * 75)
        print("🌐 [Stage 2/7] Running Benchmark 4 (Transport Channel Overhead)...")
        print("=" * 75)

        sizes = [50, 100, 200] if self.quick_mode else [100, 500, 1000]
        results = run_benchmark_channel_overhead(sizes)
        self.record_stage_result("stage_2_channel_overhead", results)

    # -----------------------------------------------------------------------
    # STAGE 3: BENCHMARK 2 - COMPONENT RUNTIME BREAKDOWN (~10s)
    # -----------------------------------------------------------------------
    def run_stage_3_component_breakdown(self) -> None:
        if self.is_stage_completed("stage_3_component_breakdown"):
            print("\n⏩ [Stage 3/7] Benchmark 2 (Component Runtime Breakdown) already COMPLETED.")
            return

        print("\n" + "=" * 75)
        print("🔬 [Stage 3/7] Running Benchmark 2 (Component Runtime Breakdown)...")
        print("=" * 75)

        size = 200 if self.quick_mode else 1000
        results = run_benchmark_component_breakdown(size)
        self.record_stage_result("stage_3_component_breakdown", results)

    # -----------------------------------------------------------------------
    # STAGE 4: BENCHMARK 5 - DATA QUALITY DECAY (~30s)
    # -----------------------------------------------------------------------
    def run_stage_4_data_decay(self) -> None:
        if self.is_stage_completed("stage_4_data_decay"):
            print("\n⏩ [Stage 4/7] Benchmark 5 (Data Quality Decay & Normalization) already COMPLETED.")
            return

        print("\n" + "=" * 75)
        print("📉 [Stage 4/7] Running Benchmark 5 (Data Quality Decay & Normalization)...")
        print("=" * 75)

        size = 200 if self.quick_mode else 1000
        noise_ratios = [0.0, 0.05, 0.10, 0.20, 0.35, 0.50]
        results = run_benchmark_data_decay(size, noise_ratios=noise_ratios)
        self.record_stage_result("stage_4_data_decay", results)

    # -----------------------------------------------------------------------
    # STAGE 5: BENCHMARK 1 - SCALABILITY & PRIVACY TAX (Up to 500,000 records)
    # -----------------------------------------------------------------------
    def run_stage_5_scalability(self) -> None:
        stage_state = self.state.setdefault("stages", {}).setdefault("stage_5_scalability", {})
        if stage_state.get("status") == "completed":
            print("\n⏩ [Stage 5/7] Benchmark 1 (Scalability up to 500,000) already COMPLETED.")
            return

        print("\n" + "=" * 75)
        print("🚀 [Stage 5/7] Running Benchmark 1 (Scalability & The Privacy Tax)...")
        print("   Target Scales: Up to 500,000 records per party (1,000,000 total)")
        print("   Granular checkpointing: Saves after each scale point.")
        print("=" * 75)

        sizes = [50, 100, 200] if self.quick_mode else [100, 1000, 10000, 50000, 100000, 500000]
        results_by_size = stage_state.setdefault("results_by_size", {})
        schema = create_cpf_schema()

        for n in sizes:
            str_n = str(n)
            if str_n in results_by_size:
                print(f"   ⏩ Scale N = {n:,} already completed in previous run (skipping).")
                continue

            overlap_count = n // 2
            print(f"\n---> [Scale N = {n:,}] Generating datasets ({overlap_count:,} overlap)...")

            db_a, db_b, _ = make_benchmark_pair(
                size_a=n,
                size_b=n,
                overlap_count=overlap_count,
                noise_ratio=0.0,
                seed=42 + n,
            )

            a_records = [row["cpf"] for row in db_a]
            b_records = [row["cpf"] for row in db_b]

            # 1. Naive SHA-256 Baseline
            t_naive_start = time.perf_counter()
            naive_matches, naive_meta = naive_sha256_psi(a_records, b_records)
            t_naive = time.perf_counter() - t_naive_start

            # 2. Commutative ECDH-PSI Exchange
            print(f"     Executing Commutative ECDH-PSI for N = {n:,}...")
            client = PSIClient(db_a, schema)
            server = PSIServer(db_b, schema)

            result, metrics = run_in_memory_psi(client, server)
            t_psi = metrics.execution_time_ms / 1000.0

            assert result.cardinality == len(naive_matches), (
                f"Match count mismatch: {result.cardinality} != {len(naive_matches)}"
            )

            privacy_tax = (t_psi / t_naive) if t_naive > 0 else float("inf")
            wire_psi = metrics.total_bytes_wire
            wire_naive = naive_meta["total_wire_bytes"]
            wire_ratio = wire_psi / wire_naive if wire_naive > 0 else float("inf")

            print(f"   ✅ [N={n:,}] Naive SHA-256: {t_naive:.4f}s | Speed: {naive_meta['records_per_sec']:9,.0f} rec/s")
            print(f"   ✅ [N={n:,}] ECDH-PSI:      {t_psi:.4f}s | Speed: {(2*n)/t_psi:9,.0f} rec/s | Wire: {wire_psi:,} B")
            print(f"   ✅ [N={n:,}] Privacy Tax:   {privacy_tax:,.1f}x CPU time | Wire: {wire_ratio:.2f}x")

            data_point = {
                "size": n,
                "overlap_count": overlap_count,
                "naive": {
                    "elapsed_seconds": t_naive,
                    "throughput_rec_per_sec": naive_meta["records_per_sec"],
                    "wire_bytes": wire_naive,
                },
                "ecdh_psi": {
                    "elapsed_seconds": t_psi,
                    "throughput_rec_per_sec": (2 * n) / t_psi if t_psi > 0 else 0,
                    "wire_bytes": wire_psi,
                },
                "privacy_tax_time_ratio": privacy_tax,
                "wire_overhead_ratio": wire_ratio,
            }

            results_by_size[str_n] = data_point
            stage_state["results_by_size"] = results_by_size
            self.save_checkpoint()

        # Convert dictionary to ordered list
        final_list = [results_by_size[str(n)] for n in sizes if str(n) in results_by_size]
        stage_state["status"] = "completed"
        stage_state["result"] = final_list
        self.save_checkpoint()

    # -----------------------------------------------------------------------
    # STAGE 6: BENCHMARK 3 - ASYMMETRIC SCALE DILEMMA (Up to 500,000 records)
    # -----------------------------------------------------------------------
    def run_stage_6_asymmetric_scale(self) -> None:
        stage_state = self.state.setdefault("stages", {}).setdefault("stage_6_asymmetric_scale", {})
        if stage_state.get("status") == "completed":
            print("\n⏩ [Stage 6/7] Benchmark 3 (Asymmetric Scale up to 500,000) already COMPLETED.")
            return

        print("\n" + "=" * 75)
        print("⚖️  [Stage 6/7] Running Benchmark 3 (Asymmetric Scale Dilemma)...")
        print("   Target Scales: Fixed Clinic |A| = 500 vs Hospital |B| up to 500,000")
        print("   Granular checkpointing: Saves after each scale point.")
        print("=" * 75)

        size_a = 200 if self.quick_mode else 500
        b_sizes = [200, 500, 1000] if self.quick_mode else [1000, 10000, 50000, 100000, 500000]
        results_by_size = stage_state.setdefault("results_by_size", {})
        schema = create_cpf_schema()

        for size_b in b_sizes:
            str_b = str(size_b)
            if str_b in results_by_size:
                print(f"   ⏩ Scale |A|={size_a} vs |B|={size_b:,} already completed in previous run (skipping).")
                continue

            overlap = min(size_a, size_b) // 2
            print(f"\n---> [Scale |A| = {size_a} vs |B| = {size_b:,}] Generating datasets ({overlap:,} overlap)...")

            db_a, db_b, _ = make_benchmark_pair(
                size_a=size_a,
                size_b=size_b,
                overlap_count=overlap,
                seed=200 + size_b,
            )

            client = PSIClient(db_a, schema)
            server = PSIServer(db_b, schema)

            result, metrics = run_in_memory_psi(client, server)
            elapsed = metrics.execution_time_ms / 1000.0

            bytes_a = metrics.total_bytes_sent_client
            bytes_b = metrics.total_bytes_sent_server
            total_bytes = metrics.total_bytes_wire
            pt_ops_per_party = size_a + size_b

            print(f"   ✅ [Scale 1:{size_b/size_a:,.1f}] Time: {elapsed:.3f}s | Ops/Party: {pt_ops_per_party:,} pts | Total Wire: {total_bytes:,} B")
            print(f"      Clinic A sent: {bytes_a:,} B | Hospital B sent: {bytes_b:,} B")

            data_point = {
                "size_a": size_a,
                "size_b": size_b,
                "ratio_b_to_a": size_b / size_a,
                "overlap_count": overlap,
                "elapsed_seconds": elapsed,
                "bytes_sent_a": bytes_a,
                "bytes_sent_b": bytes_b,
                "total_wire_bytes": total_bytes,
                "pt_ops_per_party": pt_ops_per_party,
            }

            results_by_size[str_b] = data_point
            stage_state["results_by_size"] = results_by_size
            self.save_checkpoint()

        final_list = [results_by_size[str(b)] for b in b_sizes if str(b) in results_by_size]
        stage_state["status"] = "completed"
        stage_state["result"] = final_list
        self.save_checkpoint()

    # -----------------------------------------------------------------------
    # STAGE 7: (THE LONGEST) secp256k1 EXHAUSTION ATTACK (3 Hours - Runs Last)
    # -----------------------------------------------------------------------
    def run_stage_7_secp256k1_exhaustion(self) -> None:
        stage_state = self.state.get("stages", {}).get("stage_7_secp256k1_exhaustion", {})
        if stage_state.get("status") == "completed":
            print(f"\n⏩ [Stage 7/7] secp256k1 Exhaustion Attack already COMPLETED ({stage_state['result']['attempts']:,} attempts).")
            return

        print("\n" + "=" * 75)
        print("🔒 [Stage 7/7] (LONGEST TASK - RUNNING LAST) secp256k1 Exhaustion Attack...")
        print(f"   Target Duration: {self.exhaustion_duration_seconds:,.1f}s ({self.exhaustion_duration_seconds/3600:.2f} hours)")
        print("   Progress will be saved to disk every 30 seconds.")
        print("=" * 75)

        cum_attempts = stage_state.get("attempts", 0)
        cum_elapsed = stage_state.get("elapsed_seconds", 0.0)

        base_pt = hash_to_curve(b"cpf:11:12345678901")
        secret_scalar = 0xA1B2C3D4E5F67890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0
        target_pt = point_multiply(secret_scalar, base_pt)
        target_x = target_pt.x
        target_y = target_pt.y

        base_jac = (base_pt.x, base_pt.y, 1)

        if cum_attempts > 0:
            print(f"   🔄 Resuming search from attempt #{cum_attempts + 1:,} (already ran {cum_elapsed:.1f}s)...")
            start_point = point_multiply(cum_attempts + 1, base_pt)
            curr_jac = (start_point.x, start_point.y, 1)
        else:
            curr_jac = base_jac

        t_session_start = time.perf_counter()
        last_checkpoint_time = t_session_start
        last_report_time = t_session_start
        session_attempts = 0
        cracked_scalar = None
        interrupted = False

        def _sigint_handler(sig: int, frame: Any) -> None:
            nonlocal interrupted
            print("\n\n⚠️ Interruption received! Saving current progress to checkpoint...")
            interrupted = True

        prev_handler = signal.signal(signal.SIGINT, _sigint_handler)

        try:
            while not interrupted:
                session_attempts += 1
                total_attempts = cum_attempts + session_attempts
                X, Y, Z = curr_jac

                z2 = (Z * Z) % P
                if X == (target_x * z2) % P:
                    z3 = (z2 * Z) % P
                    if Y == (target_y * z3) % P:
                        cracked_scalar = total_attempts
                        break

                curr_jac = _jacobian_add(curr_jac, base_jac)

                if (session_attempts % 10_000) == 0:
                    now = time.perf_counter()
                    session_elapsed = now - t_session_start
                    total_elapsed = cum_elapsed + session_elapsed

                    if (now - last_report_time) >= 15.0:
                        speed = session_attempts / session_elapsed if session_elapsed > 0 else 0
                        keyspace_fraction = (total_attempts / N) * 100.0
                        print(
                            f"   [{total_elapsed:7.1f}s / {total_elapsed/3600:5.2f}h] "
                            f"Attempts: {total_attempts:12,d} | "
                            f"Speed: {speed:9,.0f} pts/sec | "
                            f"Keyspace: {keyspace_fraction:.65f}%"
                        )
                        last_report_time = now

                    if (now - last_checkpoint_time) >= 30.0:
                        speed = session_attempts / session_elapsed if session_elapsed > 0 else 0
                        fraction_explored = (total_attempts / N) * 100.0
                        self.state.setdefault("stages", {})["stage_7_secp256k1_exhaustion"] = {
                            "status": "in_progress",
                            "attempts": total_attempts,
                            "elapsed_seconds": total_elapsed,
                            "ops_per_sec": speed,
                            "keyspace_fraction_percent": fraction_explored,
                            "last_checkpoint": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        }
                        self.save_checkpoint()
                        last_checkpoint_time = now

                    if total_elapsed >= self.exhaustion_duration_seconds:
                        break

        finally:
            signal.signal(signal.SIGINT, prev_handler)

        session_elapsed = time.perf_counter() - t_session_start
        total_attempts = cum_attempts + session_attempts
        total_elapsed = cum_elapsed + session_elapsed
        final_rate = session_attempts / session_elapsed if session_elapsed > 0 else 0
        fraction_explored = (total_attempts / N) * 100.0

        seconds_to_exhaust = (N / final_rate) if final_rate > 0 else float("inf")
        years_to_exhaust = seconds_to_exhaust / (365.25 * 86400)
        age_of_universe_years = 1.38e10
        universe_lifetimes = years_to_exhaust / age_of_universe_years if years_to_exhaust != float("inf") else float("inf")

        is_completed = total_elapsed >= self.exhaustion_duration_seconds or cracked_scalar is not None

        result_data = {
            "success": cracked_scalar is not None,
            "cracked_scalar": cracked_scalar,
            "attempts": total_attempts,
            "elapsed_seconds": total_elapsed,
            "elapsed_hours": total_elapsed / 3600.0,
            "ops_per_sec": final_rate,
            "keyspace_fraction_percent": fraction_explored,
            "years_to_exhaust": years_to_exhaust,
            "universe_lifetimes": universe_lifetimes,
        }

        self.state.setdefault("stages", {})["stage_7_secp256k1_exhaustion"] = {
            "status": "completed" if is_completed else "interrupted",
            "attempts": total_attempts,
            "elapsed_seconds": total_elapsed,
            "result": result_data,
        }
        self.save_checkpoint()

        print(f"\n-----------------------------------------------------------------------")
        print(f"🏁 Attack {'COMPLETED' if is_completed else 'SAVED & PAUSED'}: {'CRACKED!' if cracked_scalar else 'FAILED (Expected)'}")
        print(f"   Total Attempts Made:     {total_attempts:,}")
        print(f"   Total Time Elapsed:      {total_elapsed:.2f}s ({total_elapsed/3600:.4f} hours)")
        print(f"   Average Throughput:      {final_rate:,.1f} point ops/sec")
        print(f"   Keyspace Fraction Done:  {fraction_explored:.75f}%")
        print(f"   Time Needed to Exhaust:  {years_to_exhaust:.2e} years ({universe_lifetimes:.2e} universe lifetimes)")
        print(f"-----------------------------------------------------------------------\n")

    # -----------------------------------------------------------------------
    # CONSOLIDATE AND GENERATE FINAL ARTIFACTS
    # -----------------------------------------------------------------------
    def finalize_and_plot(self) -> None:
        stages = self.state.get("stages", {})

        metrics_data = {
            "metadata": {
                "title": "SecureMatch Comprehensive Cryptographic & Scalability Benchmark",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "quick_mode": self.quick_mode,
                "curve": "secp256k1",
                "protocol": "Commutative ECDH-PSI",
            },
            "benchmark_1_scalability": stages.get("stage_5_scalability", {}).get("result", []),
            "benchmark_2_component_breakdown": stages.get("stage_3_component_breakdown", {}).get("result", {}),
            "benchmark_3_asymmetric_scale": stages.get("stage_6_asymmetric_scale", {}).get("result", []),
            "benchmark_4_channel_overhead": stages.get("stage_2_channel_overhead", {}).get("result", []),
            "benchmark_5_data_decay": stages.get("stage_4_data_decay", {}).get("result", []),
            "security_analysis": {
                "sha_crackers": stages.get("stage_1_sha_crackers", {}).get("result", {}),
                "secp256k1_exhaustion": stages.get("stage_7_secp256k1_exhaustion", {}).get("result", {}),
            },
        }

        os.makedirs(os.path.dirname(os.path.abspath(self.metrics_path)), exist_ok=True)
        with open(self.metrics_path, "w", encoding="utf-8") as f:
            json.dump(metrics_data, f, indent=2)
        print(f"💾 Consolidated metrics written to: {self.metrics_path}")

        # Render figures
        generate_all_plots(metrics_path=self.metrics_path, out_dir=RESULTS_DIR)

    def run_all(self) -> None:
        t0 = time.perf_counter()
        print("\n" + "=" * 75)
        print("🎯 STARTING SECUREMATCH RESILIENT BENCHMARK ORCHESTRATOR")
        print(f"   Checkpoint File: {self.checkpoint_path}")
        print(f"   Scalability: Up to 500,000 records")
        print(f"   Exhaustion Target: {self.exhaustion_duration_seconds/3600:.2f} hours (Runs Last)")
        print("=" * 75)

        # 1. Quickest tasks first
        self.run_stage_1_sha_crackers()
        self.run_stage_2_channel_overhead()
        self.run_stage_3_component_breakdown()
        self.run_stage_4_data_decay()

        # 2. Scalability benchmarks (scales up to 500,000)
        self.run_stage_5_scalability()
        self.run_stage_6_asymmetric_scale()

        # 3. Longest task last (3-hour exhaustion attack)
        self.run_stage_7_secp256k1_exhaustion()

        # 4. Finalize
        self.finalize_and_plot()

        elapsed = time.perf_counter() - t0
        print(f"\n🎉 ALL EVALUATIONS AND PLOTS COMPLETED in {elapsed:.2f}s ({elapsed/3600:.2f} hours)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureMatch Resilient Benchmark Orchestrator")
    parser.add_argument("--checkpoint", type=str, default=CHECKPOINT_PATH, help="Path to checkpoint JSON")
    parser.add_argument("--duration", type=float, default=10800.0, help="Target duration in seconds for secp256k1 exhaustion (default: 10800s = 3h)")
    parser.add_argument("--quick", action="store_true", help="Quick mode for pipeline tests")
    parser.add_argument("--reset", action="store_true", help="Reset checkpoint and start from scratch")

    args = parser.parse_args()

    if args.reset and os.path.exists(args.checkpoint):
        os.remove(args.checkpoint)
        print(f"🗑️ Cleared existing checkpoint at: {args.checkpoint}")

    orchestrator = BenchmarkOrchestrator(
        checkpoint_path=args.checkpoint,
        exhaustion_duration_seconds=args.duration,
        quick_mode=args.quick,
    )
    orchestrator.run_all()
