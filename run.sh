#!/bin/bash

###############################################################################
# Security Scanner - Quick Start Script
#
# This script automates the setup and launch of the security scanner.
# Handles virtual environment creation, dependency installation, and startup.
#
# Usage: ./run.sh
###############################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║         Security Scanner - Quick Start                    ║"
echo "║         Passive Network Security Assessment Tool          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Legal warning
echo -e "${YELLOW}⚠️  LEGAL WARNING${NC}"
echo "This tool should only be used on systems you own or have"
echo "explicit written permission to scan. Unauthorized scanning"
echo "may be illegal under computer fraud and abuse laws."
echo ""
read -p "Do you have authorization to use this tool? (yes/no): " auth

if [ "$auth" != "yes" ]; then
    echo -e "${RED}Authorization not confirmed. Exiting.${NC}"
    exit 1
fi

# Check Python version
echo ""
echo -e "${GREEN}[1/4] Checking Python installation...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed.${NC}"
    echo "Please install Python 3.8 or higher from https://www.python.org/"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "Found Python $PYTHON_VERSION"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo ""
    echo -e "${GREEN}[2/4] Creating virtual environment...${NC}"
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Failed to create virtual environment.${NC}"
        exit 1
    fi
    echo "Virtual environment created successfully."
else
    echo ""
    echo -e "${GREEN}[2/4] Virtual environment already exists.${NC}"
fi

# Activate virtual environment
echo ""
echo -e "${GREEN}[3/4] Activating virtual environment...${NC}"
source venv/bin/activate

# Install dependencies
echo ""
echo -e "${GREEN}[4/4] Installing dependencies...${NC}"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to install dependencies.${NC}"
    exit 1
fi
echo "Dependencies installed successfully."

# Launch application
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Starting Security Scanner...${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "The web interface will be available at:"
echo -e "${YELLOW}http://localhost:5000${NC}"
echo ""
echo "Press Ctrl+C to stop the server."
echo ""

# Run the Flask application
python app.py
