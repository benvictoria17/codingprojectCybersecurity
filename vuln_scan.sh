#!/bin/bash

read -p "Enter the target IP address or hostname: " target

# Check if Nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "Nmap is not installed. Please install Nmap first."
    exit 1
fi

# Perform the Nmap vulnerability scan
echo "Performing Nmap vulnerability scan on $target..."
nmap -sV --script vulners $target

echo "Scan complete."
