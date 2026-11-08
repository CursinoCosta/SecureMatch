"""
End-to-End integration tests for SecureMatch Two-Party Commutative ECDH-PSI.
"""

import asyncio
import unittest
from src.data_pipeline.schema import (
    create_cnpj_schema,
    create_cpf_schema,
    create_phone_region_schema,
)
from src.protocol.party_client import PSIClient
from src.protocol.party_server import PSIServer
from src.transport.memory_channel import run_in_memory_psi
from src.transport.socket_transport import SocketPSIServer, run_socket_client


class TestProtocolE2EInMemory(unittest.TestCase):
    """End-to-end PSI tests using zero-overhead in-memory transport channel."""

    def test_complete_overlap(self):
        """When datasets are identical, intersection must be 100%."""
        schema = create_cpf_schema()
        shared_cpfs = [
            {"cpf": f"11122233{i:03d}"} for i in range(10)
        ]

        client = PSIClient(shared_cpfs, schema)
        server = PSIServer(shared_cpfs, schema)

        result, metrics = run_in_memory_psi(client, server)

        self.assertEqual(result.cardinality, 10)
        self.assertEqual(result.match_rate, 1.0)
        self.assertEqual(len(result.matched_records), 10)
        self.assertGreater(metrics.total_bytes_wire, 0)

    def test_completely_disjoint(self):
        """When datasets share no common elements, intersection must be empty."""
        schema = create_cpf_schema()
        client_data = [{"cpf": f"10000000{i:03d}"} for i in range(8)]
        server_data = [{"cpf": f"20000000{i:03d}"} for i in range(8)]

        client = PSIClient(client_data, schema)
        server = PSIServer(server_data, schema)

        result, metrics = run_in_memory_psi(client, server)

        self.assertEqual(result.cardinality, 0)
        self.assertEqual(result.match_rate, 0.0)
        self.assertEqual(len(result.matched_records), 0)

    def test_partial_overlap_cpf(self):
        """Tests partial overlap (5 shared, 5 client-only, 5 server-only)."""
        schema = create_cpf_schema()
        client_data = [
            {"cpf": "123.456.789-01"},  # shared
            {"cpf": "234.567.890-12"},  # shared
            {"cpf": "345.678.901-23"},  # shared
            {"cpf": "456.789.012-34"},  # client only
            {"cpf": "567.890.123-45"},  # client only
        ]
        server_data = [
            {"cpf": "999.888.777-66"},  # server only
            {"cpf": "23456789012"},     # shared (unformatted)
            {"cpf": "12345678901"},     # shared (unformatted)
            {"cpf": "34567890123"},     # shared (unformatted)
            {"cpf": "888.777.666-55"},  # server only
        ]

        client = PSIClient(client_data, schema)
        server = PSIServer(server_data, schema)

        result, metrics = run_in_memory_psi(client, server)

        self.assertEqual(result.cardinality, 3)
        self.assertEqual(result.matched_indices, [0, 1, 2])
        matched_cpfs = [r["cpf"] for r in result.matched_records]
        self.assertEqual(matched_cpfs, ["123.456.789-01", "234.567.890-12", "345.678.901-23"])

    def test_cnpj_schema_with_alphanumerics(self):
        """Tests PSI with CNPJs containing both numeric and modern alphanumeric entities."""
        schema = create_cnpj_schema(strict=False)

        client_data = [
            {"cnpj": "00.000.000/0001-91"},  # shared numeric
            {"cnpj": "12.ABC.345/0001-88"},  # shared alphanumeric
            {"cnpj": "99.999.999/0001-99"},  # client only
        ]
        server_data = [
            {"cnpj": "12ABC345000188"},      # shared alphanumeric (clean)
            {"cnpj": "11.111.111/0001-11"},  # server only
            {"cnpj": "00000000000191"},      # shared numeric (clean)
        ]

        client = PSIClient(client_data, schema)
        server = PSIServer(server_data, schema)

        result, _ = run_in_memory_psi(client, server)

        self.assertEqual(result.cardinality, 2)
        self.assertEqual(result.matched_indices, [0, 1])

    def test_composite_key_phone_region(self):
        """Tests PSI matching over composite keys (Phone + State)."""
        schema = create_phone_region_schema()

        client_data = [
            {"phone": "(31) 98765-4321", "region": "mg"},  # shared
            {"phone": "(11) 91234-5678", "region": "sp"},  # client only
            {"phone": "(21) 99999-0000", "region": "rj"},  # shared
        ]
        server_data = [
            {"phone": "+5531987654321", "region": "MG"},   # shared
            {"phone": "+5521999990000", "region": "RJ"},   # shared
            {"phone": "+5581977778888", "region": "PE"},   # server only
        ]

        client = PSIClient(client_data, schema)
        server = PSIServer(server_data, schema)

        result, _ = run_in_memory_psi(client, server)

        self.assertEqual(result.cardinality, 2)
        self.assertEqual(result.matched_indices, [0, 2])

    def test_schema_mismatch_rejection(self):
        """If client and server schemas do not agree, exchange must halt immediately."""
        client_schema = create_cpf_schema()
        server_schema = create_phone_region_schema()

        client = PSIClient([{"cpf": "12345678901"}], client_schema)
        server = PSIServer([{"phone": "31999998888", "region": "MG"}], server_schema)

        with self.assertRaises(ValueError) as ctx:
            run_in_memory_psi(client, server)

        self.assertIn("rejected handshake", str(ctx.exception).lower())


class TestProtocolE2ESocket(unittest.IsolatedAsyncioTestCase):
    """End-to-end PSI tests over asynchronous TCP network sockets."""

    async def test_socket_psi_exchange(self):
        """Tests full client-server exchange over localhost TCP sockets."""
        schema = create_cpf_schema()

        client_data = [
            {"cpf": "111.111.111-11"},
            {"cpf": "222.222.222-22"},
            {"cpf": "333.333.333-33"},
        ]
        server_data = [
            {"cpf": "22222222222"},  # match
            {"cpf": "44444444444"},  # no match
            {"cpf": "11111111111"},  # match
        ]

        port = 19876
        host = "127.0.0.1"

        client_logic = PSIClient(client_data, schema)
        server_logic = PSIServer(server_data, schema)

        socket_server = SocketPSIServer(server_logic, host=host, port=port)
        tcp_server = await asyncio.start_server(
            socket_server.handle_connection,
            host=host,
            port=port,
        )

        try:
            # Run client task over TCP socket
            result, metrics = await run_socket_client(client_logic, host=host, port=port)

            self.assertEqual(result.cardinality, 2)
            self.assertEqual(result.matched_indices, [0, 1])
            self.assertGreater(metrics.total_bytes_wire, 0)
            self.assertGreater(metrics.execution_time_ms, 0)

        finally:
            tcp_server.close()
            await tcp_server.wait_closed()


if __name__ == "__main__":
    unittest.main()
