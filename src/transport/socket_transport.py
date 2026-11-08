"""
Asynchronous TCP socket transport for SecureMatch.

Enables client and server to execute Private Set Intersection over standard TCP sockets
with 4-byte length-prefixed framing and wire bandwidth monitoring.
"""

from __future__ import annotations
import asyncio
import json
import struct
import time
from typing import Tuple
from ..protocol.messages import (
    ClientRound1Message,
    HandshakeRequest,
    HandshakeResponse,
    ServerRound2Message,
)
from ..protocol.party_client import IntersectionResult, PSIClient
from ..protocol.party_server import PSIServer
from .memory_channel import ChannelMetrics


async def send_framed(writer: asyncio.StreamWriter, payload: bytes) -> int:
    """Sends 4-byte length prefix followed by payload. Returns total bytes written."""
    frame = struct.pack(">I", len(payload)) + payload
    writer.write(frame)
    await writer.drain()
    return len(frame)


async def read_framed(reader: asyncio.StreamReader) -> bytes:
    """Reads 4-byte length prefix and returns the exact payload bytes."""
    header = await reader.readexactly(4)
    length = struct.unpack(">I", header)[0]
    payload = await reader.readexactly(length)
    return payload


class SocketPSIServer:
    """Listens on a TCP port and handles incoming PSI client requests."""

    def __init__(self, server_logic: PSIServer, host: str = "127.0.0.1", port: int = 9000) -> None:
        self.server_logic = server_logic
        self.host = host
        self.port = port
        self.total_bytes_sent = 0
        self.total_bytes_received = 0

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            # 1. Receive Handshake Request
            raw_req = await read_framed(reader)
            self.total_bytes_received += len(raw_req) + 4
            req_data = json.loads(raw_req.decode("utf-8"))
            req = HandshakeRequest.from_dict(req_data)

            resp = self.server_logic.handle_handshake(req)
            resp_bytes = resp.to_json().encode("utf-8")
            sent_len = await send_framed(writer, resp_bytes)
            self.total_bytes_sent += sent_len

            if resp.status != "OK":
                return

            # 2. Receive Round 1
            raw_r1 = await read_framed(reader)
            self.total_bytes_received += len(raw_r1) + 4
            m1 = ClientRound1Message(point_count=len(raw_r1) // 33, packed_points=raw_r1)

            # 3. Process & Send Round 2
            m2 = self.server_logic.process_round_1(m1)
            # Send doubly blinded points followed by server blinded points
            # Header contains counts
            meta = struct.pack(">II", m2.doubly_blinded_count, m2.server_blinded_count)
            r2_payload = meta + m2.doubly_blinded_bytes + m2.server_blinded_bytes
            sent_len = await send_framed(writer, r2_payload)
            self.total_bytes_sent += sent_len

        finally:
            writer.close()
            await writer.wait_closed()


async def run_socket_client(
    client: PSIClient,
    host: str = "127.0.0.1",
    port: int = 9000,
) -> Tuple[IntersectionResult, ChannelMetrics]:
    """Connects to a running SocketPSIServer and executes the protocol over TCP."""
    t_start = time.perf_counter()
    bytes_sent = 0
    bytes_received = 0

    reader, writer = await asyncio.open_connection(host, port)

    try:
        # 1. Handshake
        req = client.start_handshake()
        sent_len = await send_framed(writer, req.to_json().encode("utf-8"))
        bytes_sent += sent_len

        raw_resp = await read_framed(reader)
        bytes_received += len(raw_resp) + 4
        resp = HandshakeResponse.from_dict(json.loads(raw_resp.decode("utf-8")))
        client.process_handshake_response(resp)

        # 2. Round 1
        t_c1 = time.perf_counter()
        m1 = client.step_round_1()
        client_crypto_ms = (time.perf_counter() - t_c1) * 1000
        sent_len = await send_framed(writer, m1.packed_points)
        bytes_sent += sent_len

        # 3. Receive Round 2
        raw_r2 = await read_framed(reader)
        bytes_received += len(raw_r2) + 4
        c1, c2 = struct.unpack(">II", raw_r2[:8])
        doubly_bytes = raw_r2[8 : 8 + c1 * 33]
        server_bytes = raw_r2[8 + c1 * 33 : 8 + c1 * 33 + c2 * 33]

        m2 = ServerRound2Message(
            doubly_blinded_count=c1,
            server_blinded_count=c2,
            doubly_blinded_bytes=doubly_bytes,
            server_blinded_bytes=server_bytes,
        )

        # 4. Final Matching
        t_c2 = time.perf_counter()
        result = client.step_round_2(m2)
        client_crypto_ms += (time.perf_counter() - t_c2) * 1000

        total_time_ms = (time.perf_counter() - t_start) * 1000

        metrics = ChannelMetrics(
            total_bytes_sent_client=bytes_sent,
            total_bytes_sent_server=bytes_received,
            total_bytes_wire=bytes_sent + bytes_received,
            execution_time_ms=total_time_ms,
            client_crypto_time_ms=client_crypto_ms,
            server_crypto_time_ms=0.0,
        )

        return result, metrics

    finally:
        writer.close()
        await writer.wait_closed()
