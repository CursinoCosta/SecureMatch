"""
In-memory transport channel for SecureMatch.

Executes the two-party protocol directly in memory with zero operating system
socket noise, while precisely tracking payload communication volume.
"""

from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Tuple
from ..protocol.party_client import IntersectionResult, PSIClient
from ..protocol.party_server import PSIServer


@dataclass
class ChannelMetrics:
    """Tracks computation runtime and communication volume."""
    total_bytes_sent_client: int
    total_bytes_sent_server: int
    total_bytes_wire: int
    execution_time_ms: float
    client_crypto_time_ms: float
    server_crypto_time_ms: float


def run_in_memory_psi(
    client: PSIClient,
    server: PSIServer,
) -> Tuple[IntersectionResult, ChannelMetrics]:
    """
    Executes an end-to-end PSI exchange between client and server via direct memory calls.
    Returns the intersection result and detailed communication/runtime metrics.
    """
    t_start = time.perf_counter()

    # 1. Handshake
    req = client.start_handshake()
    req_bytes = req.to_json().encode("utf-8")
    client_bytes = len(req_bytes)

    resp = server.handle_handshake(req)
    resp_bytes = resp.to_json().encode("utf-8")
    server_bytes = len(resp_bytes)

    client.process_handshake_response(resp)

    # 2. Round 1: Client -> Server
    t_c1 = time.perf_counter()
    m1 = client.step_round_1()
    client_crypto_ms = (time.perf_counter() - t_c1) * 1000
    client_bytes += len(m1.packed_points)

    # 3. Round 2: Server -> Client
    t_s2 = time.perf_counter()
    m2 = server.process_round_1(m1)
    server_crypto_ms = (time.perf_counter() - t_s2) * 1000
    server_bytes += len(m2.doubly_blinded_bytes) + len(m2.server_blinded_bytes)

    # 4. Final Matching: Client
    t_c2 = time.perf_counter()
    result = client.step_round_2(m2)
    client_crypto_ms += (time.perf_counter() - t_c2) * 1000

    total_time_ms = (time.perf_counter() - t_start) * 1000

    metrics = ChannelMetrics(
        total_bytes_sent_client=client_bytes,
        total_bytes_sent_server=server_bytes,
        total_bytes_wire=client_bytes + server_bytes,
        execution_time_ms=total_time_ms,
        client_crypto_time_ms=client_crypto_ms,
        server_crypto_time_ms=server_crypto_ms,
    )

    return result, metrics
