import pytest
import logging
import socket
import struct
import threading
import time
from obd_server.doip_server import (
    DoIPServer, DoIPPayloadType, DoIPNackCodes,
    UDSServiceID, UDSNegativeResponseCode
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    
    # Should receive a NACK response with busy code
    data, _ = test_socket.recvfrom(1024)
    # Verify it's a generic header NACK (0x0000)
    assert data[2:4] == DoIPPayloadType.GENERIC_HEADER_NEGATIVE_ACK.to_bytes(2, 'big')
    # Verify the NACK code is ROUTING_ACTIVATION_BUSY (0x0A)
    assert data[8] == DoIPNackCodes.ROUTING_ACTIVATION_BUSY
    
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

def test_end_to_end_flow(doip_server, free_udp_port):
    """Test end-to-end flow: vehicle identification, TCP connection, routing activation, and Tester Present."""
    # Initialize variables that need cleanup
    udp_socket = None
    tcp_socket = None
    
    try:
        # Start server in a separate thread
        server_thread = threading.Thread(target=doip_server.start)
        server_thread.daemon = True
        server_thread.start()
        time.sleep(0.2)  # Give server more time to start
        
        # Step 1: Send vehicle identification request
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.settimeout(2.0)  # Increased timeout for reliability
        
        # Send vehicle identification request
        header = struct.pack('>BBHL', 0x02, 0xFD, DoIPPayloadType.VEHICLE_IDENTIFICATION_REQUEST, 0)
        udp_socket.sendto(header, ('127.0.0.1', doip_server.port))
        
        # Verify vehicle announcement
        data, _ = udp_socket.recvfrom(1024)
        
        # Verify DoIP header (8 bytes)
        # Protocol version (1) + Inverse version (1) + Payload type (2) + Payload length (4)
        protocol_version, inverse_version, payload_type, payload_length = struct.unpack('>BBHL', data[:8])
        
        # Verify protocol version and its inverse
        assert protocol_version == 0x02, f"Expected protocol version 0x02, got 0x{protocol_version:02X}"
        assert inverse_version == 0xFD, f"Expected inverse protocol version 0xFD, got 0x{inverse_version:02X}"
        assert protocol_version ^ inverse_version == 0xFF, "Protocol version and its inverse should be complementary"
        
        # Verify payload type
        assert payload_type == DoIPPayloadType.VEHICLE_ANNOUNCEMENT, \
            f"Expected vehicle announcement (0x{DoIPPayloadType.VEHICLE_ANNOUNCEMENT:04X}), got 0x{payload_type:04X}"
        
        # Verify payload length (VIN + Logical Address + EID + GID + Further Action)
        expected_payload_length = 17 + 2 + 6 + 6 + 1  # VIN(17) + Addr(2) + EID(6) + GID(6) + Action(1)
        assert payload_length == expected_payload_length, \
            f"Expected payload length {expected_payload_length}, got {payload_length}"
        
        # Parse payload
        payload = data[8:8+payload_length]
        
        # Verify VIN (17 bytes, ASCII)
        vin = payload[:17].decode('ascii')
        assert len(vin) == 17, f"VIN should be 17 characters, got {len(vin)}"
        assert vin == '1HGCM82633A123456', f"Unexpected VIN: {vin}"
        
        # Verify Logical Address (2 bytes, big-endian)
        logical_address = int.from_bytes(payload[17:19], 'big')
        assert logical_address == 0x0E80, f"Unexpected logical address: 0x{logical_address:04X}"
        
        # Verify EID (6 bytes)
        eid = payload[19:25]
        expected_eid = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
        assert eid == expected_eid, f"Unexpected EID: {eid.hex()}"
        
        # Verify GID (6 bytes, should be zeros)
        gid = payload[25:31]
        expected_gid = bytes([0x00] * 6)
        assert gid == expected_gid, f"Unexpected GID: {gid.hex()}"
        
        # Verify Further Action Required (1 byte, should be 0x00)
        further_action = payload[31]
        assert further_action == 0x00, f"Unexpected further action: 0x{further_action:02X}"
        
        logger.info(f"Verified vehicle announcement - VIN: {vin}, Logical Address: 0x{logical_address:04X}")
        
        # Step 2: Establish TCP connection
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.settimeout(2.0)
        tcp_socket.connect(('127.0.0.1', doip_server.port))
        
        # Step 3: Send routing activation request over TCP
        header = struct.pack('>BBHL', 0x02, 0xFD, DoIPPayloadType.ROUTING_ACTIVATION_REQUEST, 5)
        payload = struct.pack('>HB4x', 0x0E80, 0x00)  # Source address + activation type
        tcp_socket.sendall(header + payload)
        
        # Verify routing activation response
        response = tcp_socket.recv(1024)
        response_payload_type = int.from_bytes(response[2:4], 'big')
        assert response_payload_type == DoIPPayloadType.ROUTING_ACTIVATION_RESPONSE, \
            f"Expected routing activation response (0x{DoIPPayloadType.ROUTING_ACTIVATION_RESPONSE:04X}), got 0x{response_payload_type:04X}"
        
        # Step 4: Send Tester Present message
        # Create diagnostic message: source (2 bytes) + target (2 bytes) + service ID (1 byte) + sub-function (1 byte)
        diag_payload = struct.pack('>HHBB', 0x0E80, 0x0E80, UDSServiceID.TESTER_PRESENT, 0x00)
        # Create DoIP header for diagnostic message
        header = struct.pack('>BBHL', 0x02, 0xFD, DoIPPayloadType.DIAGNOSTIC_MESSAGE, len(diag_payload))
        tcp_socket.sendall(header + diag_payload)
        
        # Verify Tester Present response
        response = tcp_socket.recv(1024)
        response_payload_type = int.from_bytes(response[2:4], 'big')
        assert response_payload_type == DoIPPayloadType.DIAGNOSTIC_MESSAGE_POSITIVE_ACK, \
            f"Expected diagnostic message positive ACK (0x{DoIPPayloadType.DIAGNOSTIC_MESSAGE_POSITIVE_ACK:04X}), got 0x{response_payload_type:04X}"
        
        # The response should contain the positive response (0x7E) in the payload
        # The payload starts after the DoIP header (8 bytes) + source/target addresses (4 bytes)
        if len(response) > 12:
            assert response[12] == 0x7E, "Expected positive response SID (0x7E)"
        else:
            assert False, f"Response too short: {response.hex(' ')}"
            
    except Exception as e:
        # Log detailed error information
        import traceback
        traceback.print_exc()
        raise
        
    finally:
        # Cleanup
        if udp_socket:
            udp_socket.close()
        if tcp_socket:
            tcp_socket.close()
        doip_server.running = False
        if 'server_thread' in locals():
            server_thread.join(timeout=1.0)
