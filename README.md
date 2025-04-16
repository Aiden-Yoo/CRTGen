# CRTGen

CRTGen is a Python utility for automating the creation of SecureCRT session files. It helps you manage multiple SSH and Telnet sessions by generating session files with predefined configurations.

## Features

- Automatically creates SecureCRT session files
- Supports SSH and Telnet protocols
- Handles password encryption for SecureCRT
- Supports jump host configurations
- Creates organized directory structures for sessions

## Requirements

- Python 3.x
- PyCryptoDome
- Rich

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/crtgen.git
cd crtgen
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

CRTGen is designed to be used as a Python module in your own code. Here's how to use it:

```python
from crtgen.crt import CRT

# Your configuration
config = {
    "crt_path": "~/Documents/VanDyke/SecureCRT/Config/Sessions",
    "directory": {
        "dev": {
            "top_dir": "Development",
            "jumphost_dir": "Jumphost"
        }
    }
}

# Your session definitions
sessions = {
    "WebServers": [
        {
            "file_name": "web1.ini",
            "host": "web1.example.com",
            "username": "admin",
            "password": "secret",
            "protocol": "SSH2",
            "port": 22
        }
    ]
}

# Create CRT instance and run
crt = CRT(config, "dev", sessions)
crt.run()
```

### Default SecureCRT Session Paths

The default session paths for different operating systems are:

- **Windows**:
  ```
  C:\Documents and Settings\{USER_NAME}\Application Data\VanDyke\Config\Sessions
  ```

- **macOS**:
  ```
  /Users/{USER_NAME}/Library/Application Support/VanDyke/SecureCRT/Config/Sessions
  ```

Replace `{USER_NAME}` with your actual username.

## Security

- Supports SecureCRT's password encryption format

## License

This project is licensed under the MIT License - see the LICENSE file for details.
