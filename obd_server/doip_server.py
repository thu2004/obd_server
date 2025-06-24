"""
DoIP (Diagnostics over IP) UDP Server implementation.
Implements the ISO 13400-2 standard for vehicle diagnostics over IP.
"""

import logging
import socket
import struct
import time
from enum import IntEnum
from typing import Dict, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# DoIP Constants
DOIP_UDP_PORT = 13400
DOIP_PROTOCOL_VERSION = 0x02  # Using DoIP protocol version 2

# DoIP Payload Types (UDP)
class DoIPPayloadType(IntEnum):
    GENERIC_HEADER_NEGATIVE_ACK = 0x0000
    VEHICLE_IDENTIFICATION_REQUEST = 0x0001
    VEHICLE_IDENTIFICATION_REQUEST_WITH_EID = 0x0002
    VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN = 0x0003
    VEHICLE_ANNOUNCEMENT = 0x0004
    ROUTING_ACTIVATION_REQUEST = 0x0005
    ROUTING_ACTIVATION_RESPONSE = 0x0006
    DIAGNOSTIC_MESSAGE = 0x8001
    DIAGNOSTIC_MESSAGE_POSITIVE_ACK = 0x8002
    DIAGNOSTIC_MESSAGE_NEGATIVE_ACK = 0x8003

# UDS Service IDs
class UDSServiceID(IntEnum):
    TESTER_PRESENT = 0x3E
    DIAGNOSTIC_SESSION_CONTROL = 0x10

# UDS Negative Response Codes
class UDSNegativeResponseCode(IntEnum):
    POSITIVE_RESPONSE = 0x00
    SERVICE_NOT_SUPPORTED = 0x11
    SUB_FUNCTION_NOT_SUPPORTED = 0x12

# DoIP Generic Header Negative ACK Codes
class DoIPNackCodes(IntEnum):
    INCORRECT_PATTERN_FORMAT = 0x00
    UNKNOWN_PAYLOAD_TYPE = 0x01
    MESSAGE_TOO_LARGE = 0x02
    UNSUPPORTED_PROTOCOL_VERSION = 0x03
    ROUTING_ACTIVATION_BUSY = 0x0A  # Server is busy


class DoIPServer:
    """
    A simple DoIP UDP server that handles vehicle identification requests.
    """
    
    def __init__(self, host: str = '0.0.0.0', port: int = DOIP_UDP_PORT):
        """Initialize the DoIP server."""
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self._busy = False  # Track if server is busy
        self.active_sessions = {}  # Track active diagnostic sessions
        self.vehicle_identified = False  # Track if vehicle is identified
        self.identification_time = 0  # Timestamp of last identification
        
        # Example vehicle data (in a real implementation, this would be dynamic)
        self.vehicle_data = {
            'VIN': '1HGCM82633A123456',
            'LOGICAL_ADDRESS': 0x0E80,  # Example logical address
            'EID': bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),  # 6-byte EID
            'GID': bytes([0x00] * 6),  # 6-byte GID
            'FURTHER_ACTION_REQUIRED': 0x00  # No further action required
        }
    
    def start(self) -> None:
        """Start the DoIP server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.running = True
            
            logger.info(f"DoIP UDP Server started on {self.host}:{self.port}")
            logger.info("Waiting for vehicle identification requests...")
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(1024)  # Buffer size is 1024 bytes
                    self._handle_request(data, addr)
                except KeyboardInterrupt:
                    logger.info("Server shutting down...")
                    self.running = False
                except Exception as e:
                    logger.error(f"Error handling request: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to start DoIP server: {e}")
        finally:
            if self.socket:
                self.socket.close()
    
    def is_busy(self) -> bool:
        """Check if server is busy."""
        return self._busy
    
    def set_busy(self, busy: bool) -> None:
        """Set server busy state."""
        self._busy = busy
        status = "BUSY" if busy else "READY"
        logger.info(f"Server status changed to: {status}")
        if busy:
            logger.warning(f"Server is now busy and will reject new requests")
    
    def _send_busy_response(self, addr: Tuple[str, int], payload_type: int) -> None:
        """Send a busy response to the client."""
        try:
            if payload_type == DoIPPayloadType.ROUTING_ACTIVATION_REQUEST:
                # For routing activation, send a routing activation response with busy code
                header = struct.pack(
                    '>BBHL',
                    DOIP_PROTOCOL_VERSION,
                    0xFF ^ DOIP_PROTOCOL_VERSION,
                    DoIPPayloadType.ROUTING_ACTIVATION_RESPONSE,
                    5  # payload length (2 + 2 + 1)
                )
                payload = struct.pack(
                    '>HHB',
                    0x0E80,  # client address (placeholder)
                    self.vehicle_data['LOGICAL_ADDRESS'],
                    DoIPNackCodes.ROUTING_ACTIVATION_BUSY
                )
                self.socket.sendto(header + payload, addr)
                logger.info(f"Sent ROUTING_ACTIVATION_BUSY to {addr}")
            else:
                # For other message types, send a generic negative acknowledgment
                self._send_nack(DoIPNackCodes.ROUTING_ACTIVATION_BUSY, addr)
        except Exception as e:
            logger.error(f"Error sending busy response: {e}")
            
    def _handle_request(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle incoming DoIP requests."""
        try:
            # Parse DoIP header (8 bytes)
            if len(data) < 8:
                logger.warning(f"Invalid DoIP message (too short) from {addr}")
                return
                
            protocol_version, inverse_version, payload_type, payload_length = struct.unpack('>BBHL', data[:8])
            payload = data[8:8+payload_length] if payload_length > 0 else b''
            
            # Verify protocol version
            if protocol_version != DOIP_PROTOCOL_VERSION or inverse_version != (0xFF ^ protocol_version):
                logger.warning(f"Unsupported protocol version from {addr}")
                self._send_nack(DoIPNackCodes.UNSUPPORTED_PROTOCOL_VERSION, addr)
                return
                
            # Check if server is busy (except for vehicle identification)
            if (payload_type not in [
                DoIPPayloadType.VEHICLE_IDENTIFICATION_REQUEST,
                DoIPPayloadType.VEHICLE_IDENTIFICATION_REQUEST_WITH_EID,
                DoIPPayloadType.VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN
            ] and self.is_busy()):
                logger.warning(f"Server busy, rejecting request type 0x{payload_type:04X} from {addr}")
                self._send_busy_response(addr, payload_type)
                return
                
            # Handle different payload types
            if payload_type == DoIPPayloadType.ROUTING_ACTIVATION_REQUEST:
                self._handle_routing_activation(addr, payload)
            elif payload_type == DoIPPayloadType.VEHICLE_IDENTIFICATION_REQUEST:
                self._handle_vehicle_identification(addr, payload)
            elif payload_type == DoIPPayloadType.VEHICLE_IDENTIFICATION_REQUEST_WITH_EID:
                self._handle_vehicle_identification_with_eid(addr, payload)
            elif payload_type == DoIPPayloadType.VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN:
                self._handle_vehicle_identification_with_vin(addr, payload)
            elif payload_type == DoIPPayloadType.DIAGNOSTIC_MESSAGE:
                self._handle_diagnostic_message(addr, payload)
            else:
                logger.warning(f"Unsupported payload type: 0x{payload_type:04X} from {addr}")
                self._send_nack(DoIPNackCodes.UNKNOWN_PAYLOAD_TYPE, addr)
                
        except Exception as e:
            logger.error(f"Error processing message from {addr}: {e}")
    
    def _handle_routing_activation(self, addr: Tuple[str, int], payload: bytes) -> None:
        """Handle routing activation request."""
        try:
            if len(payload) < 7:
                logger.warning(f"Invalid routing activation request from {addr}")
                return
                
            # Parse source address and activation type
            source_address = int.from_bytes(payload[0:2], 'big')
            activation_type = payload[2]
            
            logger.info(f"Routing activation request from {addr}, source: 0x{source_address:04X}, type: {activation_type}")
            
            # In a real implementation, you would validate the activation request
            # and possibly check security credentials
            
            # Create header with correct payload type
            header = struct.pack(
                '>BBHL',
                DOIP_PROTOCOL_VERSION,
                0xFF ^ DOIP_PROTOCOL_VERSION,
                DoIPPayloadType.ROUTING_ACTIVATION_RESPONSE,
                5  # payload length (2 + 2 + 1)
            )
            # Create payload
            payload = struct.pack(
                '>HHB',
                source_address,  # client address (2 bytes)
                self.vehicle_data['LOGICAL_ADDRESS'],  # server address (2 bytes)
                0x10  # Success (1 byte)
            )
            response = header + payload
            logger.info(f"Sending routing activation response: {response.hex(' ')}")
            self.socket.sendto(response, addr)
            logger.info(f"Sent routing activation response to {addr}")
            
        except Exception as e:
            logger.error(f"Error handling routing activation from {addr}: {e}")
    
    def _handle_vehicle_identification(self, addr: Tuple[str, int], payload: bytes) -> None:
        """Handle vehicle identification request."""
        logger.info(f"Vehicle identification request from {addr}")
        try:
            # Mark vehicle as identified
            self.vehicle_identified = True
            self.identification_time = time.time()
            logger.info("Vehicle identified, diagnostic services are now available")
            
            # Create header
            header = struct.pack(
                '>BBHL',
                DOIP_PROTOCOL_VERSION,
                0xFF ^ DOIP_PROTOCOL_VERSION,
                DoIPPayloadType.VEHICLE_ANNOUNCEMENT,
                32  # VIN(17) + LA(2) + EID(6) + GID(6) + FAR(1) = 32
            )
            
            # Create payload
            payload = struct.pack(
                '>17sH6s6sB',
                self.vehicle_data['VIN'].encode('ascii'),
                self.vehicle_data['LOGICAL_ADDRESS'],
                self.vehicle_data['EID'],
                self.vehicle_data['GID'],
                self.vehicle_data['FURTHER_ACTION_REQUIRED']
            )
            
            response = header + payload
            self.socket.sendto(response, addr)
            logger.info(f"Sent vehicle announcement to {addr}")
        except Exception as e:
            logger.error(f"Error sending vehicle announcement: {e}")
    
    def _handle_vehicle_identification_with_eid(self, addr: Tuple[str, int], payload: bytes) -> None:
        """Handle vehicle identification request with EID."""
        logger.info(f"Vehicle identification request with EID from {addr}")
        # In a real implementation, you would check if the EID matches
        self._send_vehicle_announcement(addr)
    
    def _handle_vehicle_identification_with_vin(self, addr: Tuple[str, int], payload: bytes) -> None:
        """Handle vehicle identification request with VIN."""
        logger.info(f"Vehicle identification request with VIN from {addr}")
        # In a real implementation, you would check if the VIN matches
        self._send_vehicle_announcement(addr)
    
    def _send_vehicle_announcement(self, addr: Tuple[str, int]) -> None:
        """Send vehicle announcement message."""
        try:
            # Pack vehicle data
            vin_bytes = self.vehicle_data['VIN'].encode('ascii')
            eid = self.vehicle_data['EID']
            gid = self.vehicle_data['GID']
            
            # Calculate payload length: VIN(17) + LA(2) + EID(6) + GID(6) + FAR(1) = 32
            payload_length = 17 + 2 + 6 + 6 + 1
            
            # Create header
            header = struct.pack(
                '>BBHL',
                DOIP_PROTOCOL_VERSION,
                0xFF ^ DOIP_PROTOCOL_VERSION,
                DoIPPayloadType.VEHICLE_ANNOUNCEMENT,
                payload_length
            )
            
            # Create payload
            payload = struct.pack(
                f'>17sH6s6sB',
                vin_bytes,
                self.vehicle_data['LOGICAL_ADDRESS'],
                eid,
                gid,
                self.vehicle_data['FURTHER_ACTION_REQUIRED']
            )
            
            # Send response
            self.socket.sendto(header + payload, addr)
            logger.info(f"Sent vehicle announcement to {addr}")
            
        except Exception as e:
            logger.error(f"Error sending vehicle announcement to {addr}: {e}")
    
    def _send_nack(self, nack_code: int, addr: Tuple[str, int]) -> None:
        """Send a negative acknowledgment."""
        try:
            header = struct.pack(
                '>BBHL',
                DOIP_PROTOCOL_VERSION,
                0xFF ^ DOIP_PROTOCOL_VERSION,
                DoIPPayloadType.GENERIC_HEADER_NEGATIVE_ACK,
                1  # Payload length is 1 byte for NACK code
            )
            payload = struct.pack('B', nack_code)
            self.socket.sendto(header + payload, addr)
            logger.warning(f"Sent NACK with code {nack_code:02X} to {addr}")
        except Exception as e:
            logger.error(f"Error sending NACK: {e}")
            
    def _handle_diagnostic_message(self, addr: Tuple[str, int], payload: bytes) -> None:
        """Handle diagnostic messages (UDS over DoIP)."""
        try:
            if len(payload) < 5:  # 2 bytes source + 2 bytes target + 1 byte service ID
                logger.warning(f"Invalid diagnostic message from {addr}")
                return
                
            source_address = int.from_bytes(payload[0:2], 'big')
            target_address = int.from_bytes(payload[2:4], 'big')
            service_id = payload[4]
            
            # Check if vehicle is identified before processing diagnostic messages
            if not self.vehicle_identified:
                logger.warning(f"Rejecting diagnostic message: Vehicle not identified yet")
                self._send_negative_response(addr, source_address, target_address,
                                           service_id, UDSNegativeResponseCode.REQUIRE_TIME_DELAY)
                return
            
            # Update last activity for this session
            if source_address in self.active_sessions:
                self.active_sessions[source_address]['last_activity'] = time.time()
            
            # Route to appropriate handler based on service ID
            if service_id == UDSServiceID.TESTER_PRESENT:
                self._handle_tester_present(addr, source_address, target_address, payload[5:])
            elif service_id == UDSServiceID.DIAGNOSTIC_SESSION_CONTROL:
                self._handle_diagnostic_session_control(addr, source_address, target_address, payload[5:])
            else:
                logger.warning(f"Unsupported service ID: 0x{service_id:02X} from {addr}")
                self._send_negative_response(addr, source_address, target_address, 
                                           service_id, UDSNegativeResponseCode.SERVICE_NOT_SUPPORTED)
                
        except Exception as e:
            logger.error(f"Error processing diagnostic message: {e}")
    
    def _handle_tester_present(self, addr: Tuple[str, int], source_addr: int, target_addr: int, payload: bytes) -> None:
        """Handle Tester Present diagnostic message."""
        logger.info(f"Tester Present request from {addr}")
        
        try:
            # Check if we should suppress the positive response (sub-function 0x80)
            suppress_response = len(payload) > 0 and (payload[0] & 0x80) == 0x80
            
            # Update session activity
            if source_addr not in self.active_sessions:
                self.active_sessions[source_addr] = {
                    'last_activity': time.time(),
                    'session_type': 0x01  # Default session
                }
            else:
                self.active_sessions[source_addr]['last_activity'] = time.time()
            
            # Send response if not suppressing it
            if not suppress_response:
                # Create header with DIAGNOSTIC_MESSAGE_POSITIVE_ACK type
                header = struct.pack(
                    '>BBHL',
                    DOIP_PROTOCOL_VERSION,
                    0xFF ^ DOIP_PROTOCOL_VERSION,
                    DoIPPayloadType.DIAGNOSTIC_MESSAGE_POSITIVE_ACK,
                    4  # payload length (2 + 1 + 1)
                )
                # Create payload
                response_payload = struct.pack(
                    '>HBB',
                    target_addr,  # source address (tester)
                    UDSServiceID.TESTER_PRESENT + 0x40,  # Positive response SID
                    0x00  # Sub-function
                )
                response = header + response_payload
                self.socket.sendto(response, addr)
                logger.info(f"Sent Tester Present response: {response.hex(' ')} to {addr}")
                
        except Exception as e:
            logger.error(f"Error handling Tester Present: {e}")
    
    def _send_negative_response(self, addr: Tuple[str, int], source_addr: int, target_addr: int, 
                             service_id: int, nrc: int) -> None:
        """Send a negative response for UDS services."""
        try:
            # First create the UDS negative response payload
            uds_negative_response = struct.pack('>BBB', 0x7F, service_id, nrc)
            
            # Create the DoIP header with DIAGNOSTIC_MESSAGE_NEGATIVE_ACK
            header = struct.pack(
                '>BBHL',
                DOIP_PROTOCOL_VERSION,
                0xFF ^ DOIP_PROTOCOL_VERSION,
                DoIPPayloadType.DIAGNOSTIC_MESSAGE_NEGATIVE_ACK,
                4 + len(uds_negative_response)  # 4 bytes for source/target + UDS payload
            )
            
            # Create the DoIP payload with source/target addresses and UDS response
            payload = struct.pack('>HH', target_addr, source_addr) + uds_negative_response
            
            # Send the complete message
            response = header + payload
            self.socket.sendto(response, addr)
            logger.info(f"Sent negative response (NRC: 0x{nrc:02X}) to {addr}")
        except Exception as e:
            logger.error(f"Error sending negative response: {e}")
            
    def _handle_diagnostic_session_control(self, addr: Tuple[str, int], source_addr: int, 
                                        target_addr: int, payload: bytes) -> None:
        """Handle Diagnostic Session Control service (0x10)."""
        try:
            if len(payload) < 1:
                logger.warning("Invalid Diagnostic Session Control message")
                self._send_negative_response(addr, source_addr, target_addr,
                                           UDSServiceID.DIAGNOSTIC_SESSION_CONTROL,
                                           UDSNegativeResponseCode.INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT)
                return
                
            sub_function = payload[0]
            logger.info(f"Diagnostic Session Control request: sub-function 0x{sub_function:02X}")
            
            # In a real implementation, you would handle different session types here
            # For this example, we'll just accept any session type
            
            # Create positive response
            header = struct.pack(
                '>BBHL',
                DOIP_PROTOCOL_VERSION,
                0xFF ^ DOIP_PROTOCOL_VERSION,
                DoIPPayloadType.DIAGNOSTIC_MESSAGE_POSITIVE_ACK,
                7  # 2 (target) + 2 (source) + 3 (SID + sub-function + 0x00)
            )
            
            # Create payload: target address + source address + positive response
            response_payload = struct.pack(
                '>HBBB',
                target_addr,
                source_addr,
                UDSServiceID.DIAGNOSTIC_SESSION_CONTROL + 0x40,  # Positive response SID
                sub_function,  # Echo back the requested sub-function
                0x00  # No additional parameters
            )
            
            response = header + response_payload
            self.socket.sendto(response, addr)
            logger.info(f"Sent Diagnostic Session Control response to {addr}")
            
        except Exception as e:
            logger.error(f"Error handling Diagnostic Session Control: {e}")
