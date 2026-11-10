"""
Automated Comprehensive Benchmark Runner for SecureMatch.

Executes 5 rigorous empirical benchmark experiments:
1. Scalability & Privacy Tax:
   Evaluates Naive SHA-256 vs Commutative ECDH-PSI across dataset sizes N.
2. Component Runtime Breakdown:
   Profiles exact latency in Normalization, Hash-to-Curve, Point Blinding,
   Wire Transport, Remote Blinding, and Set Intersection.
3. Asymmetric Scale Dilemma:
   Evaluates performance when |A| << |B| (e.g. small specialty clinic vs large hospital).
4. CPU vs Network Channel Analysis:
   Compares in-memory channel vs asynchronous TCP socket transport.
5. Data Quality Decay & Normalization Gain:
   Measures False Negative Rate (FNR) and recall across noise ratios eta in [0%, 50%]
   comparing raw string matching vs the SecureMatch canonical normalization pipeline.

Outputs all raw and aggregated data to `benchmark/results/metrics.json`.
"""

from __future__ import annotations
import argparse
import asyncio
import json
import os
import random
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.crypto.curve import (
    Point,
    generate_private_scalar,
    point_multiply,
)
from src.crypto.hash_to_curve import hash_to_curve
from src.data_pipeline.schema import create_cpf_schema
from src.protocol.party_client import PSIClient
from src.protocol.party_server import PSIServer
from src.transport.memory_channel import run_in_memory_psi
from src.transport.socket_transport import SocketPSIServer, run_socket_client
from benchmark.generate_synthetic import (
    generate_valid_cpf_digits,
    inject_dirty_cpf,
    FIRST_NAMES,
    LAST_NAMES,
    DIAGNOSES,
)
from benchmark.baseline_naive import naive_sha256_psi


DEFAULT_OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "results", "metrics.json")


def make_benchmark_pair(
    size_a: int,
    size_b: int,
    overlap_count: int,
    noise_ratio: float = 0.0,
    seed: int = 42,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """
    Generates controlled benchmark pairs with exact overlap and configurable noise.
    Returns (db_a, db_b, shared_cpf_keys).
    """
    rng = random.Random(seed)
    total_unique = size_a + size_b - overlap_count

    # Generate unique valid CPFs
    all_cpfs = [generate_valid_cpf_digits(seed * 10000 + i) for i in range(total_unique)]
    shared_keys = all_cpfs[:overlap_count]
    only_a_keys = all_cpfs[overlap_count:size_a]
    only_b_keys = all_cpfs[size_a:total_unique]

    a_cpfs = shared_keys + only_a_keys
    b_cpfs = shared_keys + only_b_keys

    rng.shuffle(a_cpfs)
    rng.shuffle(b_cpfs)

    # Build DB A (Clean representation)
    db_a = [
        {
            "cpf": c,
            "paciente": f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}",
            "diagnostico": rng.choice(DIAGNOSES),
        }
        for c in a_cpfs
    ]

    # Build DB B (Optionally inject noise into formatting)
    db_b = []
    for c in b_cpfs:
        if rng.random() < noise_ratio:
            # Dirty style: 0 (dots/dash), 1 (spaces), 2 (dash only)
            noisy_cpf = inject_dirty_cpf(c, rng.randint(0, 2))
        else:
            noisy_cpf = c

        db_b.append({
            "cpf": noisy_cpf,
            "paciente": f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}",
            "diagnostico": rng.choice(DIAGNOSES),
        })

    return db_a, db_b, shared_keys


# ---------------------------------------------------------------------------
# BENCHMARK 1: SCALABILITY & PRIVACY TAX
# ---------------------------------------------------------------------------

def run_benchmark_scalability(
    sizes: List[int],
    overlap_ratio: float = 0.5,
) -> List[Dict[str, Any]]:
    """
    Measures execution time and wire bytes for Naive SHA-256 vs ECDH-PSI
    across symmetric dataset sizes N.
    """
    print("\n" + "=" * 75)
    print("🚀 BENCHMARK 1: Scalability & The Privacy Tax (ECDH-PSI vs Naive SHA-256)")
    print("=" * 75)

    results = []
    schema = create_cpf_schema()

    for n in sizes:
        overlap_count = int(n * overlap_ratio)
        print(f"\n---> Testing N = {n:,} (Overlap: {overlap_count:,} records)")

        db_a, db_b, expected_matches = make_benchmark_pair(
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

        # 2. ECDH-PSI Exchange (In-Memory Channel)
        client = PSIClient(db_a, schema)
        server = PSIServer(db_b, schema)

        result, metrics = run_in_memory_psi(client, server)
        t_psi = metrics.execution_time_ms / 1000.0

        # Verification
        assert result.cardinality == overlap_count, (
            f"Match count mismatch: {result.cardinality} != {overlap_count}"
        )
        assert len(naive_matches) == overlap_count

        privacy_tax_time = (t_psi / t_naive) if t_naive > 0 else float("inf")
        wire_bytes_psi = metrics.total_bytes_wire
        wire_bytes_naive = naive_meta["total_wire_bytes"]
        wire_overhead_ratio = (wire_bytes_psi / wire_bytes_naive) if wire_bytes_naive > 0 else float("inf")

        print(f"   [N={n:,}] Naive SHA-256: {t_naive:.4f}s | Throughput: {naive_meta['records_per_sec']:8,.0f} rec/s | Wire: {wire_bytes_naive:,} B")
        print(f"   [N={n:,}] ECDH-PSI:      {t_psi:.4f}s | Throughput: {(2*n)/t_psi:8,.0f} rec/s | Wire: {wire_bytes_psi:,} B")
        print(f"   [N={n:,}] Privacy Tax:   {privacy_tax_time:6.1f}x CPU time | Wire Overhead: {wire_overhead_ratio:.2f}x")

        results.append({
            "size": n,
            "overlap_count": overlap_count,
            "naive": {
                "elapsed_seconds": t_naive,
                "throughput_rec_per_sec": naive_meta["records_per_sec"],
                "wire_bytes": wire_bytes_naive,
            },
            "ecdh_psi": {
                "elapsed_seconds": t_psi,
                "throughput_rec_per_sec": (2 * n) / t_psi if t_psi > 0 else 0,
                "wire_bytes": wire_bytes_psi,
            },
            "privacy_tax_time_ratio": privacy_tax_time,
            "wire_overhead_ratio": wire_overhead_ratio,
        })

    return results


# ---------------------------------------------------------------------------
# BENCHMARK 2: COMPONENT RUNTIME BREAKDOWN
# ---------------------------------------------------------------------------

def run_benchmark_component_breakdown(
    sample_size: int = 1000,
) -> Dict[str, Any]:
    """
    Profiles the exact latency of each pipeline stage:
    1. Normalization & CRI creation
    2. Hash-to-Curve H(CRI) -> Point
    3. First Point Blinding (k * P)
    4. Serialization & In-memory Transport
    5. Second Point Blinding (k * Q)
    6. Set Intersection Match
    """
    print("\n" + "=" * 75)
    print(f"🔬 BENCHMARK 2: Pipeline Component Runtime Breakdown (N = {sample_size:,})")
    print("=" * 75)

    schema = create_cpf_schema()
    db_a, db_b, _ = make_benchmark_pair(
        size_a=sample_size,
        size_b=sample_size,
        overlap_count=sample_size // 2,
        noise_ratio=0.1,
        seed=101,
    )

    t_total_start = time.perf_counter()

    # Step 1: Normalization & CRI construction
    t0 = time.perf_counter()
    cris_a = [schema.serialize_record(r) for r in db_a]
    cris_b = [schema.serialize_record(r) for r in db_b]
    t_normalization = time.perf_counter() - t0

    # Step 2: Hash-to-Curve
    t0 = time.perf_counter()
    points_a = [hash_to_curve(cri) for cri in cris_a]
    points_b = [hash_to_curve(cri) for cri in cris_b]
    t_hash_to_curve = time.perf_counter() - t0

    # Step 3: First Blinding (k_A * P_A, k_B * P_B)
    scalar_a = generate_private_scalar()
    scalar_b = generate_private_scalar()

    t0 = time.perf_counter()
    blinded_a = [point_multiply(scalar_a, pt) for pt in points_a]
    blinded_b = [point_multiply(scalar_b, pt) for pt in points_b]
    t_first_blinding = time.perf_counter() - t0

    # Step 4: Wire Serialization & In-Memory Transport
    t0 = time.perf_counter()
    wire_bytes_a = [pt.to_compressed_bytes() for pt in blinded_a]
    wire_bytes_b = [pt.to_compressed_bytes() for pt in blinded_b]
    recv_pts_a = [Point.from_compressed_bytes(b) for b in wire_bytes_a]
    recv_pts_b = [Point.from_compressed_bytes(b) for b in wire_bytes_b]
    t_wire_transport = time.perf_counter() - t0

    # Step 5: Second Blinding (Double-blinding: k_B * blinded_a, k_A * blinded_b)
    t0 = time.perf_counter()
    double_blinded_a = [point_multiply(scalar_b, pt) for pt in recv_pts_a]
    double_blinded_b = [point_multiply(scalar_a, pt) for pt in recv_pts_b]
    t_second_blinding = time.perf_counter() - t0

    # Step 6: Set Intersection Resolution
    t0 = time.perf_counter()
    final_wire_a = {pt.to_compressed_bytes() for pt in double_blinded_a}
    final_wire_b = {pt.to_compressed_bytes() for pt in double_blinded_b}
    matches = final_wire_a.intersection(final_wire_b)
    t_intersection = time.perf_counter() - t0

    t_total = time.perf_counter() - t_total_start

    breakdown = {
        "dataset_size": sample_size,
        "total_time_seconds": t_total,
        "stages": {
            "1_normalization_and_cri": {
                "seconds": t_normalization,
                "percentage": (t_normalization / t_total) * 100.0,
            },
            "2_hash_to_curve": {
                "seconds": t_hash_to_curve,
                "percentage": (t_hash_to_curve / t_total) * 100.0,
            },
            "3_first_blinding": {
                "seconds": t_first_blinding,
                "percentage": (t_first_blinding / t_total) * 100.0,
            },
            "4_wire_serialization_and_channel": {
                "seconds": t_wire_transport,
                "percentage": (t_wire_transport / t_total) * 100.0,
            },
            "5_second_blinding": {
                "seconds": t_second_blinding,
                "percentage": (t_second_blinding / t_total) * 100.0,
            },
            "6_set_intersection_lookup": {
                "seconds": t_intersection,
                "percentage": (t_intersection / t_total) * 100.0,
            },
        },
    }

    for stage, data in breakdown["stages"].items():
        print(f"   - Stage {stage:35s}: {data['seconds']:7.4f}s ({data['percentage']:5.1f}%)")
    print(f"   => TOTAL EXECUTION TIME:             {t_total:7.4f}s (100.0%)")

    return breakdown


# ---------------------------------------------------------------------------
# BENCHMARK 3: ASYMMETRIC SCALE DILEMMA (|A| << |B|)
# ---------------------------------------------------------------------------

def run_benchmark_asymmetric_scale(
    party_a_size: int = 500,
    party_b_sizes: Optional[List[int]] = None,
) -> List[Dict[str, Any]]:
    """
    Evaluates protocol behavior under asymmetric scales:
    Hospital A has a fixed small cohort (e.g., 500 rare disease patients),
    while Hospital B has varying scales (|B| in [500, 1000, 2500, 5000]).
    """
    if party_b_sizes is None:
        party_b_sizes = [500, 1000, 2500, 5000]

    print("\n" + "=" * 75)
    print(f"⚖️  BENCHMARK 3: Asymmetric Scale Dilemma (Fixed |A| = {party_a_size:,} vs Variable |B|)")
    print("=" * 75)

    schema = create_cpf_schema()
    results = []

    for size_b in party_b_sizes:
        overlap = min(party_a_size, size_b) // 2
        print(f"\n---> Testing |A| = {party_a_size:,} vs |B| = {size_b:,} (Overlap: {overlap:,})")

        db_a, db_b, _ = make_benchmark_pair(
            size_a=party_a_size,
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
        pt_ops_per_party = party_a_size + size_b

        print(f"   [Scale 1:{size_b/party_a_size:.1f}] Total Time: {elapsed:.3f}s | Ops/Party: {pt_ops_per_party:,} pts | Total Wire: {total_bytes:,} B")
        print(f"   Clinic A sent: {bytes_a:,} B | Hospital B sent: {bytes_b:,} B")

        results.append({
            "size_a": party_a_size,
            "size_b": size_b,
            "ratio_b_to_a": size_b / party_a_size,
            "overlap_count": overlap,
            "elapsed_seconds": elapsed,
            "bytes_sent_a": bytes_a,
            "bytes_sent_b": bytes_b,
            "total_wire_bytes": total_bytes,
            "pt_ops_per_party": pt_ops_per_party,
        })

    return results


# ---------------------------------------------------------------------------
# BENCHMARK 4: CPU VS NETWORK CHANNEL OVERHEAD
# ---------------------------------------------------------------------------

async def _measure_tcp_socket(
    db_a: List[Dict[str, Any]],
    db_b: List[Dict[str, Any]],
    schema: Any,
    host: str,
    port: int,
) -> Tuple[Any, Any]:
    client_logic = PSIClient(db_a, schema)
    server_logic = PSIServer(db_b, schema)

    socket_server = SocketPSIServer(server_logic, host=host, port=port)
    tcp_server = await asyncio.start_server(
        socket_server.handle_connection,
        host=host,
        port=port,
    )

    try:
        result, metrics = await run_socket_client(client_logic, host=host, port=port)
        return result, metrics
    finally:
        tcp_server.close()
        await tcp_server.wait_closed()


def run_benchmark_channel_overhead(
    sizes: List[int],
    base_port: int = 18880,
) -> List[Dict[str, Any]]:
    """
    Compares In-Memory channel performance against Localhost TCP Socket transport.
    Quantifies the serialization, framing, and TCP socket overhead.
    """
    print("\n" + "=" * 75)
    print("🌐 BENCHMARK 4: Transport Channel Overhead (In-Memory vs Localhost TCP)")
    print("=" * 75)

    schema = create_cpf_schema()
    results = []

    for i, n in enumerate(sizes):
        port = base_port + i
        overlap = n // 2
        print(f"\n---> Testing Channel Overhead at N = {n:,} (Port {port})")

        db_a, db_b, _ = make_benchmark_pair(
            size_a=n,
            size_b=n,
            overlap_count=overlap,
            seed=300 + n,
        )

        # 1. In-Memory Run
        client_mem = PSIClient(db_a, schema)
        server_mem = PSIServer(db_b, schema)

        _, mem_metrics = run_in_memory_psi(client_mem, server_mem)
        t_mem = mem_metrics.execution_time_ms / 1000.0

        # 2. Localhost TCP Run
        _, tcp_metrics = asyncio.run(_measure_tcp_socket(db_a, db_b, schema, "127.0.0.1", port))
        t_tcp = tcp_metrics.execution_time_ms / 1000.0

        overhead_sec = t_tcp - t_mem
        overhead_percent = (overhead_sec / t_mem) * 100.0 if t_mem > 0 else 0

        print(f"   [N={n:,}] In-Memory: {t_mem:.4f}s | TCP Socket: {t_tcp:.4f}s | Delta: +{overhead_sec:.4f}s (+{overhead_percent:.1f}%)")

        results.append({
            "size": n,
            "in_memory_seconds": t_mem,
            "tcp_socket_seconds": t_tcp,
            "network_overhead_seconds": overhead_sec,
            "network_overhead_percent": overhead_percent,
        })

    return results


# ---------------------------------------------------------------------------
# BENCHMARK 5: DATA QUALITY DECAY & NORMALIZATION GAIN
# ---------------------------------------------------------------------------

def run_benchmark_data_decay(
    sample_size: int = 1000,
    noise_ratios: Optional[List[float]] = None,
) -> List[Dict[str, Any]]:
    """
    Evaluates False Negative Rate (FNR) across varying data noise ratios eta in [0%, 50%].
    Compares:
    - Raw matching: No canonicalization (fails on punctuation, spaces, case differences).
    - SecureMatch pipeline: Length-prefixed CRI with canonical field normalizers.
    """
    if noise_ratios is None:
        noise_ratios = [0.0, 0.05, 0.10, 0.20, 0.35, 0.50]

    print("\n" + "=" * 75)
    print(f"📉 BENCHMARK 5: False Negative Rate vs Data Quality Decay (N = {sample_size:,})")
    print("=" * 75)

    schema = create_cpf_schema()
    results = []
    overlap_target = sample_size // 2  # Exactly 50% true positive matches

    for eta in noise_ratios:
        print(f"\n---> Testing Noise Ratio eta = {eta*100:4.1f}% (Expected True Matches: {overlap_target:,})")

        # Generate datasets with noise injected into Party B
        db_a, db_b, expected_matches = make_benchmark_pair(
            size_a=sample_size,
            size_b=sample_size,
            overlap_count=overlap_target,
            noise_ratio=eta,
            seed=400 + int(eta * 100),
        )

        # 1. Raw Naive Matching (Without normalizers: matches raw string directly)
        raw_a = {row["cpf"] for row in db_a}
        raw_b = {row["cpf"] for row in db_b}
        raw_matched_count = len(raw_a.intersection(raw_b))
        raw_fnr = (1.0 - (raw_matched_count / overlap_target)) if overlap_target > 0 else 0
        raw_recall = (raw_matched_count / overlap_target) if overlap_target > 0 else 0

        # 2. SecureMatch Canonical Pipeline Matching
        client = PSIClient(db_a, schema)
        server = PSIServer(db_b, schema)

        result, _ = run_in_memory_psi(client, server)

        norm_matched_count = result.cardinality
        norm_fnr = (1.0 - (norm_matched_count / overlap_target)) if overlap_target > 0 else 0
        norm_recall = (norm_matched_count / overlap_target) if overlap_target > 0 else 0

        print(f"   [eta={eta*100:4.1f}%] Raw Match:  Found {raw_matched_count:4d}/{overlap_target:,} | Recall: {raw_recall*100:5.1f}% | FNR: {raw_fnr*100:5.1f}%")
        print(f"   [eta={eta*100:4.1f}%] Normalized: Found {norm_matched_count:4d}/{overlap_target:,} | Recall: {norm_recall*100:5.1f}% | FNR: {norm_fnr*100:5.1f}%")

        results.append({
            "noise_ratio": eta,
            "expected_true_matches": overlap_target,
            "raw_matching": {
                "matched_count": raw_matched_count,
                "recall_percent": raw_recall * 100.0,
                "fnr_percent": raw_fnr * 100.0,
            },
            "canonical_pipeline": {
                "matched_count": norm_matched_count,
                "recall_percent": norm_recall * 100.0,
                "fnr_percent": norm_fnr * 100.0,
            },
        })

    return results


# ---------------------------------------------------------------------------
# ORCHESTRATOR & CLI
# ---------------------------------------------------------------------------

def run_all_benchmarks(
    quick_mode: bool = False,
    output_path: str = DEFAULT_OUTPUT_PATH,
) -> Dict[str, Any]:
    """Runs all 5 benchmarks and writes the output JSON file."""
    t_start = time.perf_counter()

    if quick_mode:
        scalability_sizes = [50, 100, 200]
        breakdown_size = 200
        asymmetric_b_sizes = [200, 500, 1000]
        channel_sizes = [50, 200]
        decay_size = 200
    else:
        scalability_sizes = [100, 250, 500, 1000, 2000]
        breakdown_size = 1000
        asymmetric_b_sizes = [500, 1000, 2500, 5000]
        channel_sizes = [100, 500, 1000]
        decay_size = 1000

    metrics: Dict[str, Any] = {
        "metadata": {
            "title": "SecureMatch Comprehensive Cryptographic & Scalability Benchmark",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "quick_mode": quick_mode,
            "curve": "secp256k1",
            "protocol": "Commutative ECDH-PSI",
        },
        "benchmark_1_scalability": run_benchmark_scalability(scalability_sizes),
        "benchmark_2_component_breakdown": run_benchmark_component_breakdown(breakdown_size),
        "benchmark_3_asymmetric_scale": run_benchmark_asymmetric_scale(party_a_size=200 if quick_mode else 500, party_b_sizes=asymmetric_b_sizes),
        "benchmark_4_channel_overhead": run_benchmark_channel_overhead(channel_sizes),
        "benchmark_5_data_decay": run_benchmark_data_decay(decay_size),
    }

    total_elapsed = time.perf_counter() - t_start
    metrics["metadata"]["total_elapsed_seconds"] = total_elapsed

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print("\n" + "=" * 75)
    print(f"🎉 ALL BENCHMARKS COMPLETED in {total_elapsed:.2f}s ({total_elapsed/60:.2f} min)")
    print(f"💾 Full metrics written to: {output_path}")
    print("=" * 75 + "\n")

    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureMatch Comprehensive Benchmark Suite")
    parser.add_argument("--quick", action="store_true", help="Run with smaller datasets for rapid verification")
    parser.add_argument("--suite", type=str, default="all", choices=["all", "1", "2", "3", "4", "5"],
                        help="Run a specific benchmark suite or 'all'")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT_PATH, help="Path for JSON metrics output")

    args = parser.parse_args()

    if args.suite == "all":
        run_all_benchmarks(quick_mode=args.quick, output_path=args.output)
    elif args.suite == "1":
        sizes = [50, 100, 200] if args.quick else [100, 250, 500, 1000, 2000]
        res = run_benchmark_scalability(sizes)
        print(json.dumps(res, indent=2))
    elif args.suite == "2":
        size = 200 if args.quick else 1000
        res = run_benchmark_component_breakdown(size)
        print(json.dumps(res, indent=2))
    elif args.suite == "3":
        b_sizes = [200, 500, 1000] if args.quick else [500, 1000, 2500, 5000]
        res = run_benchmark_asymmetric_scale(party_a_size=200 if args.quick else 500, party_b_sizes=b_sizes)
        print(json.dumps(res, indent=2))
    elif args.suite == "4":
        sizes = [50, 200] if args.quick else [100, 500, 1000]
        res = run_benchmark_channel_overhead(sizes)
        print(json.dumps(res, indent=2))
    elif args.suite == "5":
        size = 200 if args.quick else 1000
        res = run_benchmark_data_decay(size)
        print(json.dumps(res, indent=2))
