"""
Security Cracker & Exhaustion Attack Demonstration for SecureMatch.

Empirically demonstrates:
1. Vulnerability of Naive Hashing:
   Brute-forces preimages for SHA-256 hashes of low-entropy identifiers:
   - Brazilian CPF (11 digits, ~10^9 space)
   - Brazilian CNPJ (14 digits, ~10^8 space for standard 0001 headquarters)
   in seconds/minutes to prove why plain hashing is vulnerable to dictionary and rainbow table attacks.
2. Computational Infeasibility of ECDLP on secp256k1:
   Launches a high-throughput brute-force discrete logarithm search against an ECDH-blinded point
   Q = k * P for a user-specified duration (e.g., seconds, minutes, or 2-3 hours), reporting:
   - Total point operations attempted
   - Instantaneous and average attempt rate (ops/sec)
   - Exact fraction of the 256-bit keyspace explored
   - Estimated astronomical years and universe lifetimes required to complete the search
   - Graceful termination on SIGINT (Ctrl+C) with persistent JSON summary dump.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import os
import signal
import sys
import time
from typing import Any, Dict, Optional, Tuple

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
from src.data_pipeline.normalizers import (
    normalize_cpf,
    validate_cpf_checksum,
    normalize_cnpj,
    validate_cnpj_checksum,
)


# ---------------------------------------------------------------------------
# PART 1: NAIVE SHA-256 PREIMAGE BRUTE-FORCE ATTACKS
# ---------------------------------------------------------------------------

def crack_naive_sha256_cpf(
    target_hash_hex: str,
    cpf_prefix_hint: Optional[str] = None,
    max_attempts: int = 20_000_000,
) -> Dict[str, Any]:
    """
    Brute-forces a target SHA-256 hash of a Brazilian CPF.

    Because CPFs have only 11 digits and the last 2 digits are deterministic MOD-11
    checksums, the effective search space is at most 10^9 (~1 billion candidates).
    If an attacker knows an area code (the 9th digit) or partial prefix, the space drops to 10^6-10^8.

    Args:
        target_hash_hex: The 64-char lowercase hex digest to crack.
        cpf_prefix_hint: Optional prefix to narrow search (e.g. '123' or '123456').
        max_attempts: Max iterations before stopping.

    Returns:
        Dictionary with attack metrics (cracked plaintext, elapsed time, hash rate).
    """
    target = target_hash_hex.lower().strip()
    t_start = time.perf_counter()
    attempts = 0
    cracked_cpf: Optional[str] = None

    # Determine start and end ranges based on prefix hint
    if cpf_prefix_hint and cpf_prefix_hint.isdigit():
        prefix_len = len(cpf_prefix_hint)
        remaining = 9 - prefix_len
        start_val = int(cpf_prefix_hint) * (10 ** remaining)
        end_val = (int(cpf_prefix_hint) + 1) * (10 ** remaining)
    else:
        # Search from 000000000 to 999999999
        start_val = 0
        end_val = 1_000_000_000

    end_val = min(end_val, start_val + max_attempts)

    for base_int in range(start_val, end_val):
        attempts += 1
        # Construct 9-digit base
        base_str = f"{base_int:09d}"

        # Fast MOD-11 check digits
        s1 = sum(int(base_str[i]) * (10 - i) for i in range(9))
        r1 = (s1 * 10) % 11
        d1 = 0 if r1 == 10 else r1

        s2 = sum(int(base_str[i]) * (11 - i) for i in range(9)) + (d1 * 2)
        r2 = (s2 * 10) % 11
        d2 = 0 if r2 == 10 else r2

        candidate_cpf = f"{base_str}{d1}{d2}"

        # Compute SHA-256 on raw 11-digit string
        digest = hashlib.sha256(candidate_cpf.encode("utf-8")).hexdigest()
        if digest == target:
            cracked_cpf = candidate_cpf
            break

    elapsed = time.perf_counter() - t_start
    hash_rate = attempts / elapsed if elapsed > 0 else 0

    return {
        "success": cracked_cpf is not None,
        "cracked_plaintext": cracked_cpf,
        "target_hash": target,
        "attempts": attempts,
        "elapsed_seconds": elapsed,
        "hash_rate_ops_per_sec": hash_rate,
    }


def crack_naive_sha256_cnpj(
    target_hash_hex: str,
    branch: str = "0001",
    cnpj_prefix_hint: Optional[str] = None,
    max_attempts: int = 20_000_000,
) -> Dict[str, Any]:
    """
    Brute-forces a target SHA-256 hash of a Brazilian CNPJ.

    Standard CNPJs have 14 digits:
    - 8 digits: company root registration
    - 4 digits: branch identifier (over 90% of healthcare headquarters use '0001')
    - 2 digits: MOD-11 checksums
    Effective search space for standard branch headquarters: 10^8 (100 million).
    With a 2 or 3-digit prefix hint (e.g., regional state registration band),
    the space drops to 10^5-10^6 candidates, crackable in seconds.

    Args:
        target_hash_hex: The 64-char lowercase hex digest to crack.
        branch: The 4-digit branch code (defaults to '0001').
        cnpj_prefix_hint: Optional root prefix (e.g. '123' or '12345').
        max_attempts: Max iterations before stopping.

    Returns:
        Dictionary with attack metrics.
    """
    target = target_hash_hex.lower().strip()
    t_start = time.perf_counter()
    attempts = 0
    cracked_cnpj: Optional[str] = None

    if cnpj_prefix_hint and cnpj_prefix_hint.isdigit():
        prefix_len = len(cnpj_prefix_hint)
        remaining = 8 - prefix_len
        start_val = int(cnpj_prefix_hint) * (10 ** remaining)
        end_val = (int(cnpj_prefix_hint) + 1) * (10 ** remaining)
    else:
        start_val = 0
        end_val = 100_000_000

    end_val = min(end_val, start_val + max_attempts)

    weights_1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    weights_2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]

    # Pre-parse branch digits
    branch_digits = [int(c) for c in branch[:4].zfill(4)]

    for base_int in range(start_val, end_val):
        attempts += 1
        base_8_str = f"{base_int:08d}"
        base_12_digits = [int(c) for c in base_8_str] + branch_digits

        # Check digit 1
        s1 = sum(base_12_digits[i] * weights_1[i] for i in range(12))
        r1 = s1 % 11
        d1 = 0 if r1 in (0, 1) else (11 - r1)

        # Check digit 2
        s2 = sum(base_12_digits[i] * weights_2[i] for i in range(12)) + (d1 * 2)
        r2 = s2 % 11
        d2 = 0 if r2 in (0, 1) else (11 - r2)

        candidate_cnpj = f"{base_8_str}{branch[:4].zfill(4)}{d1}{d2}"
        digest = hashlib.sha256(candidate_cnpj.encode("utf-8")).hexdigest()

        if digest == target:
            cracked_cnpj = candidate_cnpj
            break

    elapsed = time.perf_counter() - t_start
    hash_rate = attempts / elapsed if elapsed > 0 else 0

    return {
        "success": cracked_cnpj is not None,
        "cracked_plaintext": cracked_cnpj,
        "target_hash": target,
        "attempts": attempts,
        "elapsed_seconds": elapsed,
        "hash_rate_ops_per_sec": hash_rate,
    }


# ---------------------------------------------------------------------------
# PART 2: secp256k1 DISCRETE LOGARITHM EXHAUSTION ATTACK
# ---------------------------------------------------------------------------

def run_secp256k1_exhaustion_attack(
    target_point: Point,
    base_point: Point,
    duration_seconds: float = 10.0,
    report_interval_seconds: float = 2.0,
    output_json_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Attempts to solve the Elliptic Curve Discrete Logarithm Problem (ECDLP)
    on secp256k1 via exhaustive search for a specified duration:
    Finds k such that target_point = k * base_point.

    Uses high-throughput consecutive Jacobian additions (P, 2P, 3P, ...)
    and projective matching (X == target_x * Z^2 mod P) to avoid expensive
    modular inversions on non-matching iterations.

    Gracefully handles SIGINT (Ctrl+C), ensuring elapsed time and total attempt
    metrics are safely printed and saved to JSON.

    Args:
        target_point: The blinded curve point Q.
        base_point: The known base point P = H(record).
        duration_seconds: How long to let the brute-force search run (e.g., 7200 for 2h, 10800 for 3h).
        report_interval_seconds: Frequency of live progress console reports.
        output_json_path: Optional file path to persist summary metrics.

    Returns:
        Structured dictionary summarizing total attempts, keyspace explored, and estimated time.
    """
    t_start = time.perf_counter()
    last_report = t_start
    attempts = 0
    cracked_scalar: Optional[int] = None
    interrupted = False

    target_x = target_point.x
    target_y = target_point.y

    # Current search accumulator starting at 1 * base_point
    curr_jac = (base_point.x, base_point.y, 1)
    base_jac = (base_point.x, base_point.y, 1)

    print(f"\n=======================================================================")
    print(f"🔒 Launching secp256k1 Exhaustive Attack (Search Budget: {duration_seconds:,.1f}s / {duration_seconds/3600:.2f}h)")
    print(f"   Target Point: x = {hex(target_x)[:24]}...")
    print(f"   Base Point:   x = {hex(base_point.x)[:24]}...")
    print(f"   Group Order:  N = 2^256 (~ 1.1579 x 10^77 possibilities)")
    print(f"=======================================================================\n")

    # Signal handler for clean exit on Ctrl+C
    def _sigint_handler(sig: int, frame: Any) -> None:
        nonlocal interrupted
        print("\n\n⚠️  Interruption signal received (SIGINT). Finalizing metrics...")
        interrupted = True

    prev_handler = signal.signal(signal.SIGINT, _sigint_handler)

    try:
        while not interrupted:
            attempts += 1
            X, Y, Z = curr_jac

            # Fast Projective Match Check:
            # Affine: x = X / Z^2 mod P  ==>  X == target_x * Z^2 mod P
            z2 = (Z * Z) % P
            if X == (target_x * z2) % P:
                # Potential match on X; verify Y coordinate
                z3 = (z2 * Z) % P
                if Y == (target_y * z3) % P:
                    cracked_scalar = attempts
                    break

            # Increment accumulator: curr = curr + base (Jacobian addition)
            curr_jac = _jacobian_add(curr_jac, base_jac)

            # Check time periodically (every 5,000 steps to minimize clock query overhead)
            if (attempts % 5_000) == 0:
                now = time.perf_counter()
                if (now - last_report) >= report_interval_seconds:
                    elapsed_curr = now - t_start
                    ops_sec = attempts / elapsed_curr if elapsed_curr > 0 else 0
                    keyspace_frac = (attempts / N) * 100.0
                    hours_elapsed = elapsed_curr / 3600.0
                    print(
                        f"   [{elapsed_curr:7.1f}s / {hours_elapsed:5.2f}h] "
                        f"Attempts: {attempts:12,d} | "
                        f"Speed: {ops_sec:9,.0f} pts/sec | "
                        f"Keyspace: {keyspace_frac:.65f}%"
                    )
                    last_report = now

                if (now - t_start) >= duration_seconds:
                    break

    finally:
        signal.signal(signal.SIGINT, prev_handler)

    elapsed = time.perf_counter() - t_start
    final_rate = attempts / elapsed if elapsed > 0 else 0
    fraction_explored = (attempts / N) * 100.0

    # Calculate theoretical time to exhaust secp256k1 at this speed:
    seconds_to_exhaust = (N / final_rate) if final_rate > 0 else float("inf")
    years_to_exhaust = seconds_to_exhaust / (365.25 * 86400)
    age_of_universe_years = 1.38e10
    universe_lifetimes = years_to_exhaust / age_of_universe_years if years_to_exhaust != float("inf") else float("inf")

    print(f"\n-----------------------------------------------------------------------")
    print(f"🏁 Attack Finished: {'CRACKED!' if cracked_scalar else 'FAILED (Expected)'}")
    print(f"   Total Attempts Made:     {attempts:,}")
    print(f"   Total Time Elapsed:      {elapsed:.2f} seconds ({elapsed/3600:.4f} hours)")
    print(f"   Average Throughput:      {final_rate:,.1f} point ops/sec")
    print(f"   Keyspace Fraction Done:  {fraction_explored:.75f}%")
    print(f"   Time Needed to Exhaust:  {years_to_exhaust:.2e} years")
    print(f"   (= {universe_lifetimes:.2e} times the age of the Universe)")
    print(f"-----------------------------------------------------------------------\n")

    result = {
        "success": cracked_scalar is not None,
        "cracked_scalar": cracked_scalar,
        "attempts": attempts,
        "elapsed_seconds": elapsed,
        "elapsed_hours": elapsed / 3600.0,
        "ops_per_sec": final_rate,
        "keyspace_fraction_percent": fraction_explored,
        "years_to_exhaust": years_to_exhaust,
        "universe_lifetimes": universe_lifetimes,
    }

    if output_json_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_json_path)), exist_ok=True)
        with open(output_json_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"📁 Metrics saved to: {output_json_path}")

    return result


# ---------------------------------------------------------------------------
# CLI ENTRYPOINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureMatch Security & Cryptanalysis Demo")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. SHA-256 CPF Cracker
    p_cpf = subparsers.add_parser("crack-sha-cpf", help="Brute-force a target SHA-256 hash of a CPF")
    p_cpf.add_argument("--cpf", type=str, default="12345678909", help="CPF to hash and crack (for demo)")
    p_cpf.add_argument("--prefix-hint", type=str, default="123", help="Prefix hint to narrow search space (e.g. 123)")

    # 2. SHA-256 CNPJ Cracker
    p_cnpj = subparsers.add_parser("crack-sha-cnpj", help="Brute-force a target SHA-256 hash of a CNPJ")
    p_cnpj.add_argument("--cnpj", type=str, default="12345678000195", help="CNPJ to hash and crack (for demo)")
    p_cnpj.add_argument("--branch", type=str, default="0001", help="Branch code (default: 0001)")
    p_cnpj.add_argument("--prefix-hint", type=str, default="1234", help="Prefix hint to narrow search space (e.g. 1234)")

    # 3. secp256k1 Exhaustion Attack
    p_ec = subparsers.add_parser("exhaust-ec-dlog", help="Run brute-force discrete log attack on secp256k1")
    p_ec.add_argument("--duration", type=float, default=10.0, help="Duration to run search in seconds (e.g. 10, 60, 7200 for 2h, 10800 for 3h)")
    p_ec.add_argument("--report-every", type=float, default=2.0, help="Status report interval in seconds")
    p_ec.add_argument("--output", type=str, default=None, help="Optional JSON output file path")

    args = parser.parse_args()

    if args.subcommand == "crack-sha-cpf":
        target_cpf = args.cpf
        target_hash = hashlib.sha256(target_cpf.encode("utf-8")).hexdigest()
        print(f"\n[Target CPF]:  {target_cpf}")
        print(f"[SHA-256]:     {target_hash}")
        print(f"[Prefix Hint]: '{args.prefix_hint}' (searching matching space...)")

        res = crack_naive_sha256_cpf(target_hash, cpf_prefix_hint=args.prefix_hint)
        print(f"\nResult: {'CRACKED!' if res['success'] else 'Not found'}")
        print(f"Plaintext Recovered: {res['cracked_plaintext']}")
        print(f"Attempts:            {res['attempts']:,}")
        print(f"Time Taken:          {res['elapsed_seconds']:.3f}s")
        print(f"Hash Rate:           {res['hash_rate_ops_per_sec']:,.0f} hashes/sec\n")

    elif args.subcommand == "crack-sha-cnpj":
        target_cnpj = args.cnpj
        target_hash = hashlib.sha256(target_cnpj.encode("utf-8")).hexdigest()
        print(f"\n[Target CNPJ]: {target_cnpj}")
        print(f"[SHA-256]:     {target_hash}")
        print(f"[Branch]:      {args.branch}")
        print(f"[Prefix Hint]: '{args.prefix_hint}' (searching matching space...)")

        res = crack_naive_sha256_cnpj(target_hash, branch=args.branch, cnpj_prefix_hint=args.prefix_hint)
        print(f"\nResult: {'CRACKED!' if res['success'] else 'Not found'}")
        print(f"Plaintext Recovered: {res['cracked_plaintext']}")
        print(f"Attempts:            {res['attempts']:,}")
        print(f"Time Taken:          {res['elapsed_seconds']:.3f}s")
        print(f"Hash Rate:           {res['hash_rate_ops_per_sec']:,.0f} hashes/sec\n")

    elif args.subcommand == "exhaust-ec-dlog":
        # Create a real blinded point with a random 256-bit scalar
        base_pt = hash_to_curve(b"cpf:11:12345678901")
        secret_scalar = generate_private_scalar()
        target_pt = point_multiply(secret_scalar, base_pt)

        print(f"Real Secret Scalar: (Hidden in real life) {hex(secret_scalar)[:16]}...")
        run_secp256k1_exhaustion_attack(
            target_pt,
            base_pt,
            duration_seconds=args.duration,
            report_interval_seconds=args.report_every,
            output_json_path=args.output,
        )
