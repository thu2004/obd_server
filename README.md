# OBD Server

A Python implementation of a DoIP (Diagnostics over IP) server for vehicle diagnostics.

## Features

- Implements ISO 13400-2 standard for vehicle diagnostics over IP
- Supports vehicle identification requests
- Handles routing activation
- Processes diagnostic messages
- Command-line interface for server control

## Prerequisites

- Python 3.8+
- pip (Python package manager)

## Installation

1. Clone the repository:
   ```bash
   git clone [repository-url]
   cd obd_server
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   # On fish shell use: source venv/bin/activate.fish
   ```

3. Install the package in development mode:
   ```bash
   pip install -e .
   ```

## Usage

Start the server with the command line interface:

```bash
obd-server
```

Or run directly:

```bash
python -m obd_server.main
```

### Available Commands

- `start` - Start the DoIP server
- `stop` - Stop the DoIP server
- `busy` - Toggle server busy state
- `status` - Show server status
- `help` - Show available commands
- `exit` - Exit the program

## Development

### Running Tests

```bash
pytest
```

### Code Formatting

```bash
black .
```

### Linting

```bash
flake8
```

## License

[Specify your license here]
