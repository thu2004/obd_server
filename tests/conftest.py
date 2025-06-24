import pytest
import socket
import struct
import time
from obd_server.doip_server import DoIPServer, DoIPPayloadType, UDSServiceID, DoIPNackCodes

@pytest.fixture
def free_udp_port():
    """Find a free UDP port for testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

@pytest.fixture
def doip_server(free_udp_port):
    """Fixture to create a DoIP server for testing."""
    server = DoIPServer(host='127.0.0.1', port=free_udp_port)
    return server

@pytest.fixture
def test_socket():
    """Fixture to create a test UDP socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)  # 1 second timeout for tests
    yield sock
    sock.close()

def create_doip_header(payload_type, payload_length, version=0x02):
    """Helper to create a DoIP header."""
    return struct.pack('>BBHL', version, 0xFF ^ version, payload_type, payload_length)

def create_routing_activation_request():
    """Helper to create a routing activation request."""
    header = create_doip_header(DoIPPayloadType.ROUTING_ACTIVATION_REQUEST, 5)
    # Source address (2 bytes) + activation type (1 byte) + reserved (4 bytes)
    payload = struct.pack('>HB4x', 0x0E80, 0x00)  # Default activation type
    return header + payload

def create_tester_present_message(sub_function=0x00):
    """Helper to create a Tester Present message."""
    header = create_doip_header(DoIPPayloadType.DIAGNOSTIC_MESSAGE, 6)
    # Source (2) + Target (2) + Service ID (1) + Sub-function (1)
    payload = struct.pack('>HBB', 0x0E80, 0x0E80, UDSServiceID.TESTER_PRESENT) + bytes([sub_function])
    return header + payload
