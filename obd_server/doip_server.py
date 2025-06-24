"""
DoIP (Diagnostics over IP) UDP Server implementation.
Implements the ISO 13400-2 standard for vehicle diagnostics over IP.
"""

import logging
import socket
import struct
import time
import select
import threading
from enum import IntEnum
from typing import Dict, Tuple, List, Optional, Any

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
        self.udp_socket = None
        self.tcp_socket = None
        self.running = False
        self._busy = False  # Track if server is busy
        self.active_sessions = {}  # Track active diagnostic sessions
        self.vehicle_identified = False  # Track if vehicle is identified
        self.identification_time = 0  # Timestamp of last identification
        self.tcp_connections: List[socket.socket] = []  # Active TCP connections
        self.lock = threading.Lock()  # Thread lock for thread-safe operations
        
        # Example vehicle data (in a real implementation, this would be dynamic)
        self.vehicle_data = {
            'VIN': '1HGCM82633A123456',
            'LOGICAL_ADDRESS': 0x0E80,  # Example logical address
            'EID': bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),  # 6-byte EID
            'GID': bytes([0x00] * 6),  # 6-byte GID
            'FURTHER_ACTION_REQUIRED': 0x00  # No further action required
        }
    
    def _start_udp_server(self) -> None:
        """Start the UDP server for initial communication."""
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_socket.bind((self.host, self.port))
            self.udp_socket.settimeout(1.0)  # Add timeout to allow checking self.running
            
            logger.info(f"DoIP UDP Server started on {self.host}:{self.port}")
            logger.info("Waiting for vehicle identification requests...")
            
            # Start TCP server in a separate thread if vehicle is identified
            tcp_started = False
            
            # Continue running until stopped
            while self.running:
                try:
                    data, addr = self.udp_socket.recvfrom(1024)  # Buffer size is 1024 bytes
                    self._handle_udp_request(data, addr)
                    
                    # Start TCP server if vehicle is identified and not already started
                    if self.vehicle_identified and not tcp_started:
                        tcp_thread = threading.Thread(target=self._start_tcp_server, daemon=True)
                        tcp_thread.start()
                        tcp_started = True
                        # Small delay to ensure TCP server is ready
                        time.sleep(0.1)
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error handling UDP request: {e}", exc_info=True)
                    
        except Exception as e:
            logger.error(f"UDP server error: {e}", exc_info=True)
        finally:
            if self.udp_socket:
                self.udp_socket.close()
    
    def _start_tcp_server(self) -> None:
        """Start the TCP server for diagnostic sessions."""
        try:
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_socket.bind((self.host, self.port))
            self.tcp_socket.listen(5)
            self.tcp_socket.settimeout(1.0)  # Add timeout to allow checking self.running
            
            logger.info(f"DoIP TCP Server started on {self.host}:{self.port}")
            logger.info("Waiting for diagnostic connections...")
            
            while self.running:
                try:
                    # Check for new connections
                    read_sockets, _, _ = select.select([self.tcp_socket] + self.tcp_connections, [], [], 1.0)
                    
                    for sock in read_sockets:
                        if sock == self.tcp_socket:
                            # New connection
                            conn, addr = self.tcp_socket.accept()
                            with self.lock:
                                self.tcp_connections.append(conn)
                            logger.info(f"New diagnostic connection from {addr}")
                        else:
                            # Existing connection
                            try:
                                data = sock.recv(1024)
                                if data:
                                    # Handle diagnostic message
                                    self._handle_tcp_request(sock, data)
                                else:
                                    # Connection closed by client
                                    with self.lock:
                                        if sock in self.tcp_connections:
                                            self.tcp_connections.remove(sock)
                                    sock.close()
                                    logger.info("Diagnostic connection closed by client")
                            except Exception as e:
                                with self.lock:
                                    if sock in self.tcp_connections:
                                        self.tcp_connections.remove(sock)
                                sock.close()
                                logger.error(f"Error handling TCP connection: {e}")
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"TCP server error: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Failed to start TCP server: {e}")
        finally:
            self._cleanup_tcp()
    
    def _cleanup_tcp(self) -> None:
        """Close all TCP connections and the TCP socket."""
        with self.lock:
            for conn in self.tcp_connections:
                try:
                    conn.close()
                except:
                    pass
            self.tcp_connections = []
            
        if self.tcp_socket:
            try:
                self.tcp_socket.close()
            except:
                pass
    
    def _handle_tcp_request(self, conn: socket.socket, data: bytes) -> None:
        """Handle incoming TCP diagnostic messages."""
        try:
            # Get the client address for logging
            client_addr = conn.getpeername()
            
            # Parse the DoIP header (first 8 bytes)
            if len(data) < 8:
                logger.warning(f"Received malformed DoIP message (too short) from {client_addr}")
                return
                
            try:
                # Unpack the header
                protocol_version, _, payload_type, payload_length = struct.unpack('>BBHL', data[:8])
                payload = data[8:8+payload_length] if payload_length > 0 else b''
                
                # Log the received message
                logger.debug(f"Received DoIP message from {client_addr}, "
                           f"type: 0x{payload_type:04X}, length: {payload_length}")
                
                # Handle different payload types
                if payload_type == DoIPPayloadType.DIAGNOSTIC_MESSAGE:
                    self._handle_diagnostic_message(client_addr, payload, conn)
                elif payload_type == DoIPPayloadType.ROUTING_ACTIVATION_REQUEST:
                    self._handle_routing_activation(client_addr, payload, conn)
                elif payload_type in (DoIPPayloadType.DIAGNOSTIC_MESSAGE_POSITIVE_ACK,
                                   DoIPPayloadType.DIAGNOSTIC_MESSAGE_NEGATIVE_ACK):
                    # Handle ACKs for diagnostic messages if needed
                    logger.debug(f"Received diagnostic ACK from {client_addr}, type: 0x{payload_type:04X}")
                else:
                    logger.warning(f"Unsupported DoIP payload type 0x{payload_type:04X} from {client_addr}")
                    self._send_nack(DoIPNackCodes.UNKNOWN_PAYLOAD_TYPE, client_addr, conn)
                    
            except struct.error as e:
                logger.error(f"Failed to parse DoIP header from {client_addr}: {e}")
                self._send_nack(DoIPNackCodes.INCORRECT_PATTERN_FORMAT, client_addr, conn)
                
        except Exception as e:
            logger.error(f"Error handling TCP request from {client_addr}: {e}", exc_info=True)
            try:
                conn.close()
            except Exception as close_error:
                logger.error(f"Error closing connection: {close_error}")
    
    def start(self) -> None:
        """Start the DoIP server."""
        self.running = True
        try:
            # Start UDP server in a separate thread
            udp_thread = threading.Thread(target=self._start_udp_server, daemon=True)
            udp_thread.start()
            
            # Wait for the server to be stopped
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Server shutting down...")
            self.running = False
        except Exception as e:
            logger.error(f"Server error: {e}")
            self.running = False
        finally:
            self._cleanup_tcp()
            if self.udp_socket:
                self.udp_socket.close()
            logger.info("Server stopped")
    
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
                if self.udp_socket:
                    self.udp_socket.sendto(header + payload, addr)
                logger.info(f"Sent ROUTING_ACTIVATION_BUSY to {addr}")
            else:
                # For other message types, send a generic negative acknowledgment
                self._send_nack(DoIPNackCodes.ROUTING_ACTIVATION_BUSY, addr)
        except Exception as e:
            logger.error(f"Error sending busy response: {e}")
            
    def _handle_udp_request(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle incoming DoIP request."""
        try:
            if len(data) < 8:  # Minimum DoIP header size
                logger.warning(f"Received malformed DoIP message (too short) from {addr}")
                return
                
            # Parse DoIP header
            protocol_version, _, payload_type, payload_length = struct.unpack('>BBHL', data[:8])
            payload = data[8:8+payload_length] if payload_length > 0 else b''
            
            # Log the received message
            logger.debug(f"Received DoIP message from {addr}, type: 0x{payload_type:04X}, length: {payload_length}")
            
            # Check protocol version
            if protocol_version != DOIP_PROTOCOL_VERSION:
                logger.warning(f"Unsupported protocol version: 0x{protocol_version:02X} from {addr}")
                self._send_nack(DoIPNackCodes.UNSUPPORTED_PROTOCOL_VERSION, addr)
                return
                
            # Handle different payload types
            if payload_type == DoIPPayloadType.VEHICLE_IDENTIFICATION_REQUEST:
                self._handle_vehicle_identification(addr, payload)
            elif payload_type == DoIPPayloadType.ROUTING_ACTIVATION_REQUEST:
                self._handle_routing_activation(addr, payload)
            elif payload_type == DoIPPayloadType.DIAGNOSTIC_MESSAGE:
                self._handle_diagnostic_message(addr, payload)
            else:
                logger.warning(f"Unsupported payload type from {addr}: 0x{payload_type:04X}")
                self._send_nack(DoIPNackCodes.UNKNOWN_PAYLOAD_TYPE, addr)
                
        except Exception as e:
            logger.error(f"Error handling request from {addr}: {e}", exc_info=True)
    
    def _handle_routing_activation(self, addr: Tuple[str, int], payload: bytes, tcp_conn: socket.socket = None) -> None:
        """Handle routing activation request.
        
        Args:
            addr: Tuple of (ip, port) for the client
            payload: Raw payload data from the request
            tcp_conn: Optional TCP socket connection if this is a TCP request
        """
        try:
            # Minimum length is 5 bytes (2 bytes source address + 1 byte activation type + 2 bytes reserved)
            if len(payload) < 5:
                logger.warning(f"Invalid routing activation request length {len(payload)} from {addr}")
                if tcp_conn:
                    self._send_nack(DoIPNackCodes.INCORRECT_PATTERN_FORMAT, addr, tcp_conn)
                return
                
            # Parse routing activation request
            source_address, activation_type = struct.unpack('>HB', payload[:3])
            
            logger.info(f"Routing activation request from {addr}, source: 0x{source_address:04X}, type: {activation_type}")
            
            # Check if server is busy
            if self._busy:
                logger.warning(f"Server busy, rejecting routing activation from {addr}")
                self._send_nack(DoIPNackCodes.ROUTING_ACTIVATION_BUSY, addr, tcp_conn)
                return
            
            # In a real implementation, you would validate the activation request
            # and potentially maintain a list of active clients
            response_code = 0x10  # Success
            
            # Create response header
            header = struct.pack(
                '>BBHL',
                DOIP_PROTOCOL_VERSION,
                0xFF ^ DOIP_PROTOCOL_VERSION,
                DoIPPayloadType.ROUTING_ACTIVATION_RESPONSE,
                5  # payload length (2 + 2 + 1)
            )
            
            # Create response payload
            response_payload = struct.pack(
                '>HHB',
                source_address,  # client address
                self.vehicle_data['LOGICAL_ADDRESS'],  # server address
                response_code
            )
            
            # Send response
            response = header + response_payload
            logger.info(f"Sending routing activation response: {response.hex(' ')}")
            
            if tcp_conn:
                # Send response over TCP
                try:
                    tcp_conn.sendall(response)
                    logger.debug(f"Sent routing activation response to TCP client {addr}")
                except Exception as e:
                    logger.error(f"Error sending routing activation response to {addr} over TCP: {e}")
            elif self.udp_socket:
                # Send response over UDP
                try:
                    self.udp_socket.sendto(response, addr)
                    logger.debug(f"Sent routing activation response to UDP client {addr}")
                except Exception as e:
                    logger.error(f"Error sending routing activation response to {addr} over UDP: {e}")
            else:
                logger.error("No socket available to send routing activation response")
            
        except Exception as e:
            logger.error(f"Error handling routing activation from {addr}: {e}", exc_info=True)
            # Try to send a generic error response if this was a TCP request
            if tcp_conn:
                try:
                    self._send_nack(DoIPNackCodes.INCORRECT_PATTERN_FORMAT, addr, tcp_conn)
                except Exception as inner_e:
                    logger.error(f"Failed to send error response: {inner_e}")
    
    def _handle_vehicle_identification(self, addr: Tuple[str, int], payload: bytes) -> None:
        """Handle vehicle identification request."""
        try:
            logger.info(f"Vehicle identification request from {addr}")
            
            # Mark vehicle as identified
            self.vehicle_identified = True
            self.identification_time = time.time()
            
            # Send vehicle announcement
            self._send_vehicle_announcement(addr)
            
            logger.info("Vehicle identified, diagnostic services are now available")
            
        except Exception as e:
            logger.error(f"Error handling vehicle identification from {addr}: {e}")
            # Re-raise to help with debugging test failures
            raise
    
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
            if self.udp_socket:
                self.udp_socket.sendto(header + payload, addr)
                logger.info("Vehicle identified, TCP diagnostic server activated")
            logger.info(f"Sent vehicle announcement to {addr}")
            
        except Exception as e:
            logger.error(f"Error sending vehicle announcement: {e}")
            # Re-raise to help with debugging test failures
            raise
    
    def _send_nack(self, nack_code: int, addr: Tuple[str, int], tcp_conn: socket.socket = None) -> None:
        """Send a negative acknowledgment.
        
        Args:
            nack_code: The NACK code to send
            addr: Tuple of (ip, port) for the client
            tcp_conn: Optional TCP socket connection if this is a TCP request
        """
        try:
            header = struct.pack(
                '>BBHL',
                DOIP_PROTOCOL_VERSION,
                0xFF ^ DOIP_PROTOCOL_VERSION,
                DoIPPayloadType.GENERIC_HEADER_NEGATIVE_ACK,
                1  # Payload length is 1 byte for NACK code
            )
            payload = struct.pack('B', nack_code)
            try:
                if tcp_conn:
                    # Send over TCP connection
                    tcp_conn.sendall(header + payload)
                elif self.udp_socket:
                    # Send over UDP
                    self.udp_socket.sendto(header + payload, addr)
                else:
                    logger.error("No connection available to send NACK response")
                logger.warning(f"Sent NACK with code {nack_code:02X} to {addr}")
            except Exception as e:
                logger.error(f"Error sending NACK: {e}")
                
        except Exception as e:
            logger.error(f"Error sending NACK: {e}")

    def _handle_diagnostic_message(self, addr: Tuple[str, int], payload: bytes, tcp_conn: socket.socket = None) -> None:
        """Handle diagnostic message.
        
        Args:
            addr: Tuple of (ip, port) for the client
            payload: Raw payload data from the request
            tcp_conn: Optional TCP socket connection if this is a TCP request
        """
        try:
            logger.debug(f"Received diagnostic message: {payload.hex(' ')} from {addr}")
            
            # Check minimum message length: source(2) + target(2) + at least 1 byte payload
            if len(payload) < 5:  
                logger.warning(f"Diagnostic message too short from {addr}")
                if tcp_conn:  # Only send NACK for TCP connections
                    self._send_nack(DoIPNackCodes.INVALID_PAYLOAD_LENGTH, addr, tcp_conn)
                return
                
            # Parse source and target addresses
            source_address = int.from_bytes(payload[0:2], 'big')
            target_address = int.from_bytes(payload[2:4], 'big')
            diag_payload = payload[4:]
            
            if not diag_payload:
                logger.warning(f"Empty diagnostic payload from {addr}")
                self._send_negative_response(
                    addr, source_address, target_address,
                    0x00,  # Service ID not available
                    UDSNegativeResponseCode.INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT,
                    tcp_conn
                )
                return
                
            # Get service ID (first byte of payload)
            service_id = diag_payload[0]
            service_payload = diag_payload[1:]  # Payload without service ID
            
            logger.info(f"Diagnostic message from {addr}, source: 0x{source_address:04X}, "
                        f"target: 0x{target_address:04X}, service: 0x{service_id:02X}")
            
            # Check if vehicle is identified for non-TesterPresent messages
            if service_id != UDSServiceID.TESTER_PRESENT and not self.vehicle_identified:
                logger.warning(f"Rejecting diagnostic message: Vehicle not identified yet")
                self._send_negative_response(
                    addr, source_address, target_address,
                    service_id,
                    UDSNegativeResponseCode.REQUEST_SEQUENCE_ERROR,
                    tcp_conn
                )
                return
            
            # Route to appropriate handler based on service ID
            if service_id == UDSServiceID.TESTER_PRESENT:
                logger.debug("Handling Tester Present message")
                self._handle_tester_present(addr, source_address, target_address, service_payload, tcp_conn)
            elif service_id == UDSServiceID.DIAGNOSTIC_SESSION_CONTROL:
                logger.debug("Handling Diagnostic Session Control message")
                self._handle_diagnostic_session_control(addr, source_address, target_address, service_payload, tcp_conn)
            else:
                logger.warning(f"Unsupported service ID: 0x{service_id:02X} from {addr}")
                self._send_negative_response(
                    addr, source_address, target_address,
                    service_id,
                    UDSNegativeResponseCode.SERVICE_NOT_SUPPORTED,
                    tcp_conn
                )
                
        except Exception as e:
            logger.error(f"Error handling diagnostic message from {addr}: {e}", exc_info=True)
            # Try to send a generic error response if possible
            try:
                if len(payload) >= 4:  # If we have valid source/target addresses
                    source_address = int.from_bytes(payload[0:2], 'big')
                    target_address = int.from_bytes(payload[2:4], 'big')
                    service_id = payload[4] if len(payload) > 4 else 0x00
                    self._send_negative_response(
                        addr, source_address, target_address,
                        service_id,
                        UDSNegativeResponseCode.GENERAL_REJECT,
                        tcp_conn
                    )
            except Exception as inner_e:
                logger.error(f"Failed to send error response: {inner_e}")

    def _handle_tester_present(self, addr: Tuple[str, int], source_addr: int, target_addr: int, 
                             payload: bytes, tcp_conn: socket.socket = None) -> None:
        """Handle Tester Present diagnostic message (0x3E).
        
        Args:
            addr: Tuple of (ip, port) for the client
            source_addr: Source address of the diagnostic message
            target_addr: Target address of the diagnostic message
            payload: Raw payload data from the request (after service ID)
            tcp_conn: Optional TCP socket connection if this is a TCP request
        """
        logger.info(f"Tester Present request from {addr}, source: 0x{source_addr:04X}, "
                   f"target: 0x{target_addr:04X}, payload: {payload.hex(' ')}")
        
        try:
            # Check for minimum payload length (sub-function byte)
            if len(payload) < 1:
                logger.warning("Tester Present message too short, missing sub-function")
                self._send_negative_response(
                    addr, source_addr, target_addr,
                    UDSServiceID.TESTER_PRESENT,
                    UDSNegativeResponseCode.INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT,
                    tcp_conn
                )
                return
            
            # Get sub-function (first byte of payload)
            sub_function = payload[0]
            logger.debug(f"Tester Present sub-function: 0x{sub_function:02X}")
            
            # Only sub-function 0x00 (suppressPosRspMsgIndicationBit not set) is supported
            # Sub-function 0x80 is also valid but doesn't require a response
            if sub_function not in (0x00, 0x80):
                logger.warning(f"Unsupported Tester Present sub-function: 0x{sub_function:02X}")
                self._send_negative_response(
                    addr, source_addr, target_addr,
                    UDSServiceID.TESTER_PRESENT,
                    UDSNegativeResponseCode.SUB_FUNCTION_NOT_SUPPORTED,
                    tcp_conn
                )
                return
            
            # For sub-function 0x00, send positive response
            if sub_function == 0x00:
                # Positive response format: 0x7E (positive response) + service ID (0x3E) + sub-function (0x00)
                response = struct.pack('>BB', 0x7E, UDSServiceID.TESTER_PRESENT)
                
                # Create DoIP header
                header = struct.pack(
                    '>BBHL',
                    DOIP_PROTOCOL_VERSION,
                    0xFF ^ DOIP_PROTOCOL_VERSION,
                    DoIPPayloadType.DIAGNOSTIC_MESSAGE_POSITIVE_ACK,
                    4 + len(response)  # 2 bytes source + 2 bytes target + payload
                )
                
                # Create full message with addresses
                message = header + struct.pack('>HH', target_addr, source_addr) + response
                
                logger.info(f"Sending Tester Present positive response to {addr}")
                
                # Send response back to the client
                try:
                    if tcp_conn:
                        # Send over TCP connection
                        tcp_conn.sendall(message)
                    elif self.udp_socket:
                        # Send over UDP
                        self.udp_socket.sendto(message, addr)
                    else:
                        logger.error("No connection available to send Tester Present response")
                except Exception as send_error:
                    logger.error(f"Error sending Tester Present response: {send_error}")
            else:
                # For sub-function 0x80, no response is sent (suppress positive response)
                logger.debug("Tester Present with suppress positive response flag set, no response sent")
                response_payload = struct.pack('>BB', 0x7E, 0x00)  # 0x3E + 0x40 = 0x7E
                
                # Create DoIP header
                header = struct.pack(
                    '>BBHL',
                    DOIP_PROTOCOL_VERSION,
                    0xFF ^ DOIP_PROTOCOL_VERSION,
                    DoIPPayloadType.DIAGNOSTIC_MESSAGE,
                    4 + len(response_payload)  # 2 bytes source + 2 bytes target + payload
                )
                
                # Create full message with addresses and payload
                message = header + struct.pack('>HH', target_addr, source_addr) + response_payload
                
                logger.info(f"Sending Tester Present response to {addr}")
                logger.debug(f"Response message: {message.hex(' ')}")
                
                if self.udp_socket:
                    try:
                        sent = self.udp_socket.sendto(message, addr)
                        logger.debug(f"Successfully sent {sent} bytes to {addr}")
                        logger.debug(f"Socket info: {self.udp_socket}")
                        logger.debug(f"Socket type: {type(self.udp_socket)}")
                        logger.debug(f"Socket family: {self.udp_socket.family}")
                        logger.debug(f"Socket type: {self.udp_socket.type}")
                        logger.debug(f"Socket proto: {self.udp_socket.proto}")
                        logger.debug(f"Socket timeout: {self.udp_socket.gettimeout()}")
                    except Exception as e:
                        logger.error(f"Error sending response: {e}", exc_info=True)
                else:
                    logger.error("Cannot send response: UDP socket not available")
                    
        except Exception as e:
            logger.error(f"Error handling Tester Present: {e}", exc_info=True)

    def _send_negative_response(self, addr: Tuple[str, int], source_addr: int, target_addr: int, 
                             service_id: int, nrc: int, tcp_conn: socket.socket = None) -> None:
        """Send a negative response for UDS services.
        
        Args:
            addr: Tuple of (ip, port) for the client
            source_addr: Source address of the diagnostic message
            target_addr: Target address of the diagnostic message
            service_id: The service ID that failed
            nrc: Negative Response Code
            tcp_conn: Optional TCP socket connection if this is a TCP request
        """
        try:
            # Create UDS negative response payload (0x7F + SID + NRC)
            uds_negative_response = struct.pack('>BBB', 0x7F, service_id, nrc)
            
            # Create DoIP header
            header = struct.pack(
                '>BBHL',
                DOIP_PROTOCOL_VERSION,
                0xFF ^ DOIP_PROTOCOL_VERSION,
                DoIPPayloadType.DIAGNOSTIC_MESSAGE_NEGATIVE_ACK,
                4 + len(uds_negative_response)  # 2 bytes source + 2 bytes target + payload
            )
            
            # Create full message with addresses
            message = header + struct.pack('>HH', target_addr, source_addr) + uds_negative_response
            
            logger.info(f"Sending negative response to {addr}, service: 0x{service_id:02X}, NRC: 0x{nrc:02X}")
            
            if tcp_conn:
                # Send over TCP connection
                tcp_conn.sendall(message)
            elif self.udp_socket:
                # Send over UDP
                self.udp_socket.sendto(message, addr)
            else:
                logger.error("No connection available to send NACK response")
                
        except Exception as e:
            logger.error(f"Error sending negative response: {e}")
            raise

    def _handle_diagnostic_session_control(self, addr: Tuple[str, int], source_addr: int, 
                                        target_addr: int, payload: bytes, tcp_conn: socket.socket = None) -> None:
        """Handle Diagnostic Session Control service (0x10).
        
        Args:
            addr: Tuple of (ip, port) for the client
            source_addr: Source address of the diagnostic message
            target_addr: Target address of the diagnostic message
            payload: Raw payload data from the request
            tcp_conn: Optional TCP socket connection if this is a TCP request
        """
        try:
            if len(payload) < 1:
                logger.warning("Invalid Diagnostic Session Control message")
                self._send_negative_response(
                    addr, source_addr, target_addr,
                    UDSServiceID.DIAGNOSTIC_SESSION_CONTROL,
                    UDSNegativeResponseCode.INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT,
                    tcp_conn
                )
                return

            # In a real implementation, you would handle different session types here
            # For now, just send a positive response for any session type
            session_type = payload[0]
            logger.info(f"Starting diagnostic session type: 0x{session_type:02X}")
            
            # Create response header
            header = struct.pack(
                '>BBHL',
                DOIP_PROTOCOL_VERSION,
                0xFF ^ DOIP_PROTOCOL_VERSION,
                DoIPPayloadType.DIAGNOSTIC_MESSAGE_POSITIVE_ACK,
                4 + 3  # payload length (4 for addresses + 3 for UDS response)
            )
            
            # Create response payload (UDS positive response: SID + 0x40, sub-function, [data])
            response_payload = struct.pack(
                '>HHB',
                target_addr,  # target address (ECU)
                source_addr,  # source address (tester)
                0x40 | UDSServiceID.DIAGNOSTIC_SESSION_CONTROL  # Positive Response SID
            ) + bytes([session_type])  # Echo back the session type
            
            # Send response
            response = header + response_payload
            
            if tcp_conn:
                # Send over TCP connection
                tcp_conn.sendall(response)
            elif self.udp_socket:
                # Send over UDP
                self.udp_socket.sendto(response, addr)
            else:
                logger.error("No connection available to send diagnostic response")
                return
                
            logger.info(f"Sent Diagnostic Session Control response to {addr}")
                
        except Exception as e:
            logger.error(f"Error in _handle_diagnostic_session_control: {e}")
            raise
