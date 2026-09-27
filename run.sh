#!/usr/bin/env bash
# Network Autopsy Launch Script
set -e

echo "=========================================="
echo "      Starting Network Autopsy System     "
echo "=========================================="

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required. Please install Python 3.11+."
    exit 1
fi

# Check permissions for raw sockets/scapy
if [ "$EUID" -ne 0 ]; then
    echo "[Notice] Running without root/sudo. Active socket fallbacks will be used."
    echo "[Notice] For full raw-socket ICMP crafting and Scapy passive sniffing, run with sudo."
fi

# Install dependencies if needed
if [ -f "requirements.txt" ]; then
    echo "Checking dependencies..."
    python3 -m pip install -r requirements.txt --quiet || true
fi

# Launch system
python3 main.py
