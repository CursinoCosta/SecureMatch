"""
Server state machine for SecureMatch Commutative ECDH-PSI.
"""

from __future__ import annotations
import secrets
from enum import Enum
from typing import Any, Dict, List, Optional
from ..crypto.curve import Point, generate_private_scalar
from ..crypto.engine import blind_point, blind_points, hash_and_blind, hash_and_blind_batch
from ..data_pipeline.schema import Schema
from .messages import (
    ClientRound1Message,
    HandshakeRequest,
    HandshakeResponse,
    ServerRound2Message,
)


class ServerState(str, Enum):
    IDLE = "IDLE"
    HANDSHAKE_COMPLETED = "HANDSHAKE_COMPLETED"
    ROUND_1_PROCESSED = "ROUND_1_PROCESSED"
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"


class PSIServer:
    """
    Two-party Commutative ECDH-PSI Server.
    Holds private dataset Y, private scalar b, and state machine.
    """

    def __init__(
        self,
        records: List[Dict[str, Any]],
        schema: Schema,
        private_scalar: Optional[int] = None,
    ) -> None:
        self.raw_records = records
        self.schema = schema
        self.scalar_b = private_scalar if private_scalar is not None else generate_private_scalar()

        self.state = ServerState.IDLE
        self.cri_records: List[bytes] = []
        self.client_dataset_size: int = 0

    def handle_handshake(self, request: HandshakeRequest) -> HandshakeResponse:
        """Validates incoming client handshake proposal."""
        # Pre-process local records into CRI byte strings
        self.cri_records = [self.schema.serialize_record(r) for r in self.raw_records]

        local_fingerprint = self.schema.fingerprint()

        if request.schema_fingerprint != local_fingerprint:
            self.state = ServerState.ERROR
            return HandshakeResponse(
                status="SCHEMA_MISMATCH_ERROR",
                schema_fingerprint=local_fingerprint,
                server_dataset_size=len(self.cri_records),
                error_message=(
                    f"Client schema fingerprint ({request.schema_fingerprint[:16]}...) "
                    f"does not match server schema ({local_fingerprint[:16]}...)."
                ),
            )

        self.client_dataset_size = request.dataset_size
        self.state = ServerState.HANDSHAKE_COMPLETED

        return HandshakeResponse(
            status="OK",
            schema_fingerprint=local_fingerprint,
            server_dataset_size=len(self.cri_records),
        )

    def process_round_1(self, message: ClientRound1Message) -> ServerRound2Message:
        """
        Processes client Round 1 message:
        1. Multiplies incoming client points by scalar b:
           P_{ba,i} = b * P_{a,i} = (b * a) * H(x_i)
        2. Computes and blinds server's own records:
           P_{b,j} = b * H(y_j)
        3. Cryptographically shuffles server's blinded points (Fisher-Yates)
           to eliminate any positional correlation.
        """
        if self.state != ServerState.HANDSHAKE_COMPLETED:
            raise RuntimeError(f"Cannot process Round 1 in state: {self.state}")

        client_points = message.get_points()

        # 1. Double-blind client points: P_{ba,i} = b * P_{a,i}
        # (Preserves client's index ordering so client can map matches locally)
        doubly_blinded = blind_points(self.scalar_b, client_points)

        # 2. Blind server's own dataset: P_{b,j} = b * H(y_j)
        server_blinded = hash_and_blind_batch(self.scalar_b, self.cri_records)

        # 3. Cryptographically random shuffle using CSPRNG
        rng = secrets.SystemRandom()
        rng.shuffle(server_blinded)

        self.state = ServerState.COMPLETED

        return ServerRound2Message.create(
            doubly_blinded=doubly_blinded,
            server_blinded=server_blinded,
        )
