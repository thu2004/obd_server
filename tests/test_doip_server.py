import pytest
import socket
import struct
import threading
import time
from obd_server.doip_server import (
    DoIPServer, DoIPPayloadType, DoIPNackCodes,
    UDSServiceID, UDSNegativeResponseCode
)

def test_server_initialization(doip_server):
    """Test that the server initializes correctly."""
    assert doip_server is not None
    assert doip_server.running is False
    assert doip_server.is_busy() is False

def test_unsupported_protocol_version(doip_server, test_socket):
    """Test handling of unsupported protocol version."""
    # Start server in a separate thread
    server_thread = threading.Thread(target=doip_server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # Give server time to start
    time.sleep(0.1)
    
    # Send message with unsupported version
    test_socket.sendto(b'\x01\xFE\x00\x01\x00\x00\x00\x00', 
                      ('127.0.0.1', doip_server.port))
    
    # Should receive a NACK with unsupported version code
    data, _ = test_socket.recvfrom(1024)
    assert data[4:6] == DoIPPayloadType.GENERIC_HEADER_NEGATIVE_ACK.to_bytes(2, 'big')
    assert data[8] == DoIPNackCodes.UNSUPPORTED_PROTOCOL_VERSION
    
    # Cleanup
    doip_server.running = False
    server_thread.join(timeout=1.0)

def test_routing_activation(doip_server, test_socket):
    """Test routing activation request handling."""
    server_thread = threading.Thread(target=doip_server.start)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(0.1)
    
    # Create and send routing activation request
    header = struct.pack('>BBHL', 0x02, 0xFD, DoIPPayloadType.ROUTING_ACTIVATION_REQUEST, 7)
    payload = struct.pack('>HBBBBB', 0x0E80, 0x00, 0x00, 0x00, 0x00, 0x00)
    test_socket.sendto(header + payload, ('127.0.0.1', doip_server.port))
    
    # Should receive a positive response
    data, _ = test_socket.recvfrom(1024)
    assert data[2:4] == DoIPPayloadType.ROUTING_ACTIVATION_RESPONSE.to_bytes(2, 'big')
    
    # Cleanup
    doip_server.running = False
    server_thread.join(timeout=1.0)

def test_tester_present(doip_server, test_socket):
    """Test Tester Present service."""
    server_thread = threading.Thread(target=doip_server.start)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(0.1)
    
    # First activate routing
    header = struct.pack('>BBHL', 0x02, 0xFD, DoIPPayloadType.ROUTING_ACTIVATION_REQUEST, 7)
    payload = struct.pack('>HBBBBB', 0x0E80, 0x00, 0x00, 0x00, 0x00, 0x00)
    test_socket.sendto(header + payload, ('127.0.0.1', doip_server.port))
    test_socket.recvfrom(1024)  # Discard response
    
    # Send Tester Present with response (sub-function 0x00 - with response)
    # Payload: source address (2) + target address (2) + service ID (1) + sub-function (1)
    header = struct.pack('>BBHL', 0x02, 0xFD, DoIPPayloadType.DIAGNOSTIC_MESSAGE, 6)
    payload = struct.pack('>HHBB', 0x0E80, 0x0E80, UDSServiceID.TESTER_PRESENT, 0x00)
    test_socket.sendto(header + payload, ('127.0.0.1', doip_server.port))
    
    # Should receive a positive response
    data, _ = test_socket.recvfrom(1024)
    assert data[2:4] == DoIPPayloadType.DIAGNOSTIC_MESSAGE_POSITIVE_ACK.to_bytes(2, 'big')
    assert data[10] == (UDSServiceID.TESTER_PRESENT + 0x40)  # Positive response SID
    
    # Test Tester Present without response (sub-function 0x80 - no response)
    header = struct.pack('>BBHL', 0x02, 0xFD, DoIPPayloadType.DIAGNOSTIC_MESSAGE, 6)
    payload = struct.pack('>HHBB', 0x0E80, 0x0E80, UDSServiceID.TESTER_PRESENT, 0x80)
    test_socket.sendto(header + payload, ('127.0.0.1', doip_server.port))
    
    # Should not receive a response (timeout will raise exception)
    with pytest.raises(socket.timeout):
        test_socket.settimeout(0.5)
        test_socket.recvfrom(1024)
    
    # Cleanup
    doip_server.running = False
    server_thread.join(timeout=1.0)

def test_busy_state(doip_server, test_socket):
    """Test server busy state handling."""
    server_thread = threading.Thread(target=doip_server.start)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(0.1)
    
    # Set server to busy
    doip_server.set_busy(True)
    
    # Send routing activation request
    header = struct.pack('>BBHL', 0x02, 0xFD, DoIPPayloadType.ROUTING_ACTIVATION_REQUEST, 7)
    payload = struct.pack('>HBBBBB', 0x0E80, 0x00, 0x00, 0x00, 0x00, 0x00)
    test_socket.sendto(header + payload, ('127.0.0.1', doip_server.port))
    
    # Should receive a busy response
    data, _ = test_socket.recvfrom(1024)
    assert data[2:4] == DoIPPayloadType.ROUTING_ACTIVATION_RESPONSE.to_bytes(2, 'big')
    assert data[12] == DoIPNackCodes.ROUTING_ACTIVATION_BUSY
    
    # Cleanup
    doip_server.running = False
    server_thread.join(timeout=1.0)

def test_vehicle_identification(doip_server, test_socket):
    """Test vehicle identification request."""
    server_thread = threading.Thread(target=doip_server.start)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(0.1)
    
    # Send vehicle identification request
    header = struct.pack('>BBHL', 0x02, 0xFD, DoIPPayloadType.VEHICLE_IDENTIFICATION_REQUEST, 0)
    test_socket.sendto(header, ('127.0.0.1', doip_server.port))
    
    # Should receive a vehicle announcement
    data, _ = test_socket.recvfrom(1024)
    assert data[2:4] == DoIPPayloadType.VEHICLE_ANNOUNCEMENT.to_bytes(2, 'big')
    
    # Cleanup
    doip_server.running = False
    server_thread.join(timeout=1.0)
