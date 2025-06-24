"""
Main entry point for the DoIP (Diagnostics over IP) UDP Server.
Provides a command-line interface to control the DoIP server.
"""

import logging
import socket
import sys
import threading
from typing import Tuple

from .doip_server import DoIPServer, DOIP_UDP_PORT

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CommandInterface:
    """
    Command-line interface for controlling the DoIP server.
    """
    
    def __init__(self, server: DoIPServer):
        """Initialize the command interface with a DoIP server instance."""
        self.server = server
        self.running = False
        self.commands = {
            'start': self.start_server,
            'stop': self.stop_server,
            'busy': self.toggle_busy,
            'status': self.show_status,
            'help': self.show_help,
            'exit': self.exit
        }
    
    def start(self) -> None:
        """Start the command interface."""
        self.running = True
        print("DoIP Server Control Interface")
        print("Type 'help' for available commands\n")
        
        try:
            while self.running:
                try:
                    command = input("doip> ").strip().lower()
                    if not command:
                        continue
                        
                    if command in self.commands:
                        self.commands[command]()
                    else:
                        print(f"Unknown command: {command}. Type 'help' for available commands.")
                except KeyboardInterrupt:
                    print("\nUse 'exit' to quit or 'help' for commands")
                except Exception as e:
                    logger.error(f"Command error: {e}")
        except EOFError:
            print("\nExiting...")
        finally:
            self.cleanup()
    
    def start(self):
        """Start the command interface."""
        self.running = True
        print("DoIP Server Control Interface")
        print("Type 'help' for available commands\n")
        
        try:
            while self.running:
                try:
                    command = input("doip> ").strip().lower()
                    if not command:
                        continue
                        
                    if command in self.commands:
                        self.commands[command]()
                    else:
                        print(f"Unknown command: {command}. Type 'help' for available commands.")
                except KeyboardInterrupt:
                    print("\nUse 'exit' to quit or 'help' for commands")
                except Exception as e:
                    logger.error(f"Command error: {e}")
        except EOFError:
            print("\nExiting...")
        finally:
            self.cleanup()
    
    def start_server(self):
        """Start the DoIP server."""
        if not hasattr(self, 'server_thread') or not self.server_thread.is_alive():
            self.server.running = True
            self.server_thread = threading.Thread(target=self.server.start)
            self.server_thread.daemon = True
            self.server_thread.start()
            print("Server started")
        else:
            print("Server is already running")
    
    def stop_server(self):
        """Stop the DoIP server."""
        if hasattr(self, 'server_thread') and self.server_thread.is_alive():
            self.server.running = False
            # Send a dummy packet to unblock the socket
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(b'', ('127.0.0.1', self.server.port))
            except Exception:
                pass
            self.server_thread.join(timeout=2)
            print("Server stopped")
        else:
            print("Server is not running")
    
    def toggle_busy(self):
        """Toggle the server's busy state."""
        busy = not self.server.is_busy()
        self.server.set_busy(busy)
        print(f"Server busy state: {'BUSY' if busy else 'READY'}")
    
    def show_status(self):
        """Show server status information."""
        status = {
            'Server': 'RUNNING' if hasattr(self, 'server_thread') and self.server_thread.is_alive() else 'STOPPED',
            'Busy State': 'BUSY' if self.server.is_busy() else 'READY',
            'Port': self.server.port,
            'Active Sessions': len(self.server.active_sessions)
        }
        
        print("\nServer Status:")
        for key, value in status.items():
            print(f"{key}: {value}")
        print()
    
    def show_help(self):
        """Show available commands."""
        commands = {
            'start': 'Start the DoIP server',
            'stop': 'Stop the DoIP server',
            'busy': 'Toggle server busy state',
            'status': 'Show server status',
            'help': 'Show this help message',
            'exit': 'Exit the program'
        }
        
        print("\nAvailable commands:")
        for cmd, desc in commands.items():
            print(f"  {cmd:<8} - {desc}")
        print()
    
    def exit(self):
        """Exit the program."""
        self.stop_server()
        self.running = False
        print("Goodbye!")
    
    def cleanup(self):
        """Clean up resources."""
        if hasattr(self, 'server_thread') and self.server_thread.is_alive():
            self.stop_server()


def main() -> None:
    """Run the DoIP server with command interface."""
    try:
        server = DoIPServer()
        cli = CommandInterface(server)
        cli.start()
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
