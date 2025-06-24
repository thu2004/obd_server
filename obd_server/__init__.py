"""
ODB Server - A Python implementation of a DoIP (Diagnostics over IP) server.

This package provides a server implementation of the ISO 13400-2 standard
for vehicle diagnostics over IP, including support for UDS (Unified Diagnostic Services).
"""

from .doip_server import DoIPServer, DOIP_UDP_PORT
from .main import CommandInterface, main

__version__ = "0.1.0"

__all__ = [
    'DoIPServer',
    'CommandInterface',
    'main',
    'DOIP_UDP_PORT',
    '__version__',
]
