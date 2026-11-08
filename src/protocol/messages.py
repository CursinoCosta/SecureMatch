"""
Protocol message framing, serialization, and point packing for SecureMatch PSI.
"""

from __future__ import annotations
import json
import struct
from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple
from ..crypto.curve import Point


class MessageType(str, Enum):
    HANDSHAKE_REQUEST = "HANDSHAKE_REQUEST"
    HANDSHAKE_RESPONSE = "HANDSHAKE_RESPONSE"
    CLIENT_ROUND_1 = "CLIENT_ROUND_1"
    SERVER_ROUND_2 = "SERVER_ROUND_2"
    ERROR = "ERROR"


def pack_points(points: List[Point]) -> bytes:
    """Serializes a list of Points into a contiguous byte stream of 33-byte compressed points."""
    return b"".join(pt.to_compressed_bytes() for pt in points)


def unpack_points(buffer: bytes) -> List[Point]:
    """Deserializes a contiguous byte stream into a list of Point instances."""
    if len(buffer) % 33 != 0:
        raise ValueError(f"Buffer length ({len(buffer)}) is not a multiple of 33 bytes.")
    points: List[Point] = []
    for i in range(0, len(buffer), 33):
        chunk = buffer[i : i + 33]
        points.append(Point.from_compressed_bytes(chunk))
    return points


@dataclass
class HandshakeRequest:
    schema_id: str
    schema_fingerprint: str
    dataset_size: int

    def to_json(self) -> str:
        return json.dumps({
            "type": MessageType.HANDSHAKE_REQUEST.value,
            "schema_id": self.schema_id,
            "schema_fingerprint": self.schema_fingerprint,
            "dataset_size": self.dataset_size,
        })

    @classmethod
    def from_dict(cls, data: dict) -> "HandshakeRequest":
        return cls(
            schema_id=data["schema_id"],
            schema_fingerprint=data["schema_fingerprint"],
            dataset_size=data["dataset_size"],
        )


@dataclass
class HandshakeResponse:
    status: str  # "OK" or "SCHEMA_MISMATCH_ERROR"
    schema_fingerprint: str
    server_dataset_size: int
    error_message: str = ""

    def to_json(self) -> str:
        return json.dumps({
            "type": MessageType.HANDSHAKE_RESPONSE.value,
            "status": self.status,
            "schema_fingerprint": self.schema_fingerprint,
            "server_dataset_size": self.server_dataset_size,
            "error_message": self.error_message,
        })

    @classmethod
    def from_dict(cls, data: dict) -> "HandshakeResponse":
        return cls(
            status=data["status"],
            schema_fingerprint=data["schema_fingerprint"],
            server_dataset_size=data["server_dataset_size"],
            error_message=data.get("error_message", ""),
        )


@dataclass
class ClientRound1Message:
    point_count: int
    packed_points: bytes

    @classmethod
    def create(cls, points: List[Point]) -> "ClientRound1Message":
        return cls(point_count=len(points), packed_points=pack_points(points))

    def get_points(self) -> List[Point]:
        return unpack_points(self.packed_points)


@dataclass
class ServerRound2Message:
    doubly_blinded_count: int
    server_blinded_count: int
    doubly_blinded_bytes: bytes  # Shuffled b * (a * H(x))
    server_blinded_bytes: bytes  # b * H(y)

    @classmethod
    def create(
        cls,
        doubly_blinded: List[Point],
        server_blinded: List[Point],
    ) -> "ServerRound2Message":
        return cls(
            doubly_blinded_count=len(doubly_blinded),
            server_blinded_count=len(server_blinded),
            doubly_blinded_bytes=pack_points(doubly_blinded),
            server_blinded_bytes=pack_points(server_blinded),
        )

    def get_doubly_blinded_points(self) -> List[Point]:
        return unpack_points(self.doubly_blinded_bytes)

    def get_server_blinded_points(self) -> List[Point]:
        return unpack_points(self.server_blinded_bytes)
