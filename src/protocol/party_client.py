"""
Client state machine for SecureMatch Commutative ECDH-PSI.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from ..crypto.curve import Point, generate_private_scalar
from ..crypto.engine import blind_point, blind_points, hash_and_blind, hash_and_blind_batch
from ..data_pipeline.schema import Schema
from .messages import (
    ClientRound1Message,
    HandshakeRequest,
    HandshakeResponse,
    ServerRound2Message,
)


class ClientState(str, Enum):
    IDLE = "IDLE"
    HANDSHAKE_SENT = "HANDSHAKE_SENT"
    ROUND_1_SENT = "ROUND_1_SENT"
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"


@dataclass
class IntersectionResult:
    """Holds the final Private Set Intersection results for the client."""
    matched_indices: List[int]
    matched_records: List[Dict[str, Any]]
    matched_cris: List[bytes]
    client_dataset_size: int
    server_dataset_size: int

    @property
    def cardinality(self) -> int:
        return len(self.matched_indices)

    @property
    def match_rate(self) -> float:
        if self.client_dataset_size == 0:
            return 0.0
        return self.cardinality / self.client_dataset_size


class PSIClient:
    """
    Two-party Commutative ECDH-PSI Client.
    Holds private dataset X, private scalar a, and state machine.
    """

    def __init__(
        self,
        records: List[Dict[str, Any]],
        schema: Schema,
        private_scalar: Optional[int] = None,
    ) -> None:
        self.raw_records = records
        self.schema = schema
        self.scalar_a = private_scalar if private_scalar is not None else generate_private_scalar()

        self.state = ClientState.IDLE
        self.cri_records: List[bytes] = []
        self.client_blinded_points: List[Point] = []
        self.server_dataset_size: int = 0

    def start_handshake(self) -> HandshakeRequest:
        """Initiates session handshake by proposing schema and dataset size."""
        # Pre-process local records to CRI byte strings
        self.cri_records = [self.schema.serialize_record(r) for r in self.raw_records]

        req = HandshakeRequest(
            schema_id=self.schema.schema_id,
            schema_fingerprint=self.schema.fingerprint(),
            dataset_size=len(self.cri_records),
        )
        self.state = ClientState.HANDSHAKE_SENT
        return req

    def process_handshake_response(self, response: HandshakeResponse) -> None:
        """Processes and validates the server's handshake response."""
        if self.state != ClientState.HANDSHAKE_SENT:
            raise RuntimeError(f"Unexpected handshake response in state: {self.state}")

        if response.status != "OK":
            self.state = ClientState.ERROR
            raise ValueError(f"Server rejected handshake: {response.error_message}")

        if response.schema_fingerprint != self.schema.fingerprint():
            self.state = ClientState.ERROR
            raise ValueError(
                f"Schema fingerprint mismatch! Client: {self.schema.fingerprint()}, "
                f"Server: {response.schema_fingerprint}"
            )

        self.server_dataset_size = response.server_dataset_size

    def step_round_1(self) -> ClientRound1Message:
        """
        Round 1: Client maps records to curve points and blinds them with scalar a.
        P_{a,i} = a * H(x_i)
        """
        if self.state != ClientState.HANDSHAKE_SENT:
            raise RuntimeError("Must complete handshake before executing Round 1.")

        self.client_blinded_points = hash_and_blind_batch(self.scalar_a, self.cri_records)
        msg = ClientRound1Message.create(self.client_blinded_points)
        self.state = ClientState.ROUND_1_SENT
        return msg

    def step_round_2(self, response: ServerRound2Message) -> IntersectionResult:
        """
        Round 2: Client receives:
        1. doubly_blinded_points: P_{ba,i} = b * P_{a,i} = (b * a) * H(x_i)
        2. server_blinded_points: Shuffled S_b = { b * H(y_j) }

        Client blinds server points with scalar a:
        P_{ab,j} = a * S_{b,j} = (a * b) * H(y_j)
        Constructs lookup table T = { P_{ab,j} }
        Determines matches: index i is matched if P_{ba,i} in T.
        """
        if self.state != ClientState.ROUND_1_SENT:
            raise RuntimeError(f"Unexpected Round 2 execution in state: {self.state}")

        doubly_blinded = response.get_doubly_blinded_points()
        server_blinded = response.get_server_blinded_points()

        if len(doubly_blinded) != len(self.cri_records):
            raise ValueError(
                f"Server returned {len(doubly_blinded)} doubly-blinded points, "
                f"expected {len(self.cri_records)}."
            )

        # Compute P_{ab,j} = a * P_{b,j} for all server points
        # and store their 33-byte compressed representations in a fast set
        blinded_server_pts = blind_points(self.scalar_a, server_blinded)
        server_lookup: Set[bytes] = {
            pt.to_compressed_bytes() for pt in blinded_server_pts
        }

        matched_indices: List[int] = []
        matched_records: List[Dict[str, Any]] = []
        matched_cris: List[bytes] = []

        # For each local record i, check if its doubly-blinded point exists in server table
        for idx, p_ba in enumerate(doubly_blinded):
            p_ba_bytes = p_ba.to_compressed_bytes()
            if p_ba_bytes in server_lookup:
                matched_indices.append(idx)
                matched_records.append(self.raw_records[idx])
                matched_cris.append(self.cri_records[idx])

        self.state = ClientState.COMPLETED

        return IntersectionResult(
            matched_indices=matched_indices,
            matched_records=matched_records,
            matched_cris=matched_cris,
            client_dataset_size=len(self.cri_records),
            server_dataset_size=len(server_blinded),
        )
