# SimplePortScanner

SimplePortScanner is a lightweight, multi-threaded network port scanner written in Python.  
It supports scanning single IPs, ranges of IPs, or entire subnets, and allows you to scan single ports, ranges of ports, or common service ports.

> **Disclaimer:**  
> This tool is intended for educational purposes and authorized testing only.  
> Unauthorized port scanning is illegal and unethical. Please ensure you have explicit permission before scanning any network or system.

## Features

- **IP Range Input:**  
  Accepts a single IP (e.g., `192.168.1.1`), a dash-separated range (e.g., `192.168.1.1-192.168.1.10`), or a CIDR subnet (e.g., `192.168.1.0/24`).

- **Port Range Input:**  
  Supports single ports (e.g., `80`), ranges (e.g., `20-80`), and well-known service names (e.g., `http`, `ftp`).

- **Multi-Threading:**  
  Uses Python's `ThreadPoolExecutor` to perform concurrent port scans for faster results.

- **Logging:**  
  Scan results are logged to `port_scanner.log` for later review.

## Requirements

- Python 3.x

## Usage

Run the script from the command line:

```bash
python3 simple_port_scanner.py --ip_range <IP_RANGE> --port_range <PORT_RANGE> [--timeout <TIMEOUT>] [--threads <THREAD_COUNT>]
```

## Example
- Scan a single IP for HTTP (port 80):
  ```bash
  python3 simple_port_scanner.py --ip_range 192.168.1.100 --port_range http
  ```

- Scan a range of IPs for SSH (port 22):
  ```bash
  python3 simple_port_scanner.py --ip_range 192.168.1.1-192.168.1.10 --port_range 22
  ```

- Scan a subnet for a range of ports:
  ```bash
  python3 simple_port_scanner.py --ip_range 192.168.1.0/24 --port_range 20-80
  ```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/C0deRhin0/Simple_Port_Scanner.git
   ```

2. Navigate to the project directory:
   ```bash
   cd Simple_Port_Scanner
   ```

3. Running the script:
   Refer to "Example" section

OR you can just download the file in this repo and run it

## License
This project is licensed under the [MIT License](LICENSE).

## Contact

For any inquiries or support, please contact:

- **Author**: C0deRhin0 
- **GitHub**: [C0deRhin0](https://github.com/C0deRhin0)

---
