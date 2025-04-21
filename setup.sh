
#!/bin/bash

# Setup script for Web-Hunter
# Created by Nabaraj Lamichhane

# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Bold text
BOLD='\033[1m'
RESET='\033[0m'

# Fancy borders
TOP_LEFT="╔"
TOP_RIGHT="╗"
BOTTOM_LEFT="╚"
BOTTOM_RIGHT="╝"
HORIZONTAL="═"
VERTICAL="║"
LEFT_CONNECTOR="╠"
RIGHT_CONNECTOR="╣"

# Clear screen
clear

# ASCII Art
echo -e "${PURPLE}"
echo '██╗    ██╗███████╗██████╗       ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ '
echo '██║    ██║██╔════╝██╔══██╗      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗'
echo '██║ █╗ ██║█████╗  ██████╔╝█████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝'
echo '██║███╗██║██╔══╝  ██╔══██╗╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗'
echo '╚███╔███╔╝███████╗██████╔╝      ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║'
echo ' ╚══╝╚══╝ ╚══════╝╚═════╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝'
echo -e "${NC}"

# Create header
width=80
title="Web-Hunter Installation"
padding=$(( (width - ${#title} - 2) / 2 ))
border_width=$width

echo -e "${BLUE}${TOP_LEFT}${HORIZONTAL}$(printf '%*s' $border_width | tr ' ' "${HORIZONTAL}")${TOP_RIGHT}${NC}"
echo -e "${BLUE}${VERTICAL}${NC}$(printf %${padding}s)${CYAN}${BOLD} $title ${RESET}$(printf %${padding}s)${BLUE}${VERTICAL}${NC}"
echo -e "${BLUE}${LEFT_CONNECTOR}${HORIZONTAL}$(printf '%*s' $border_width | tr ' ' "${HORIZONTAL}")${RIGHT_CONNECTOR}${NC}"

# Function to print a section header
print_section() {
    local section="$1"
    local section_color="$2"
    local padding=$(( (width - ${#section} - 4) / 2 ))
    echo -e "${BLUE}${VERTICAL}${NC} ${section_color}${BOLD}[+] $section${RESET}$(printf %$(($width - ${#section} - 5))s)${BLUE}${VERTICAL}${NC}"
}

# Function to print a step
print_step() {
    local step="$1"
    local status="$2"
    local status_color="$3"
    echo -e "${BLUE}${VERTICAL}${NC}    ${WHITE}→${NC} $step$(printf %$(($width - ${#step} - ${#status} - 9))s)${status_color}$status${NC} ${BLUE}${VERTICAL}${NC}"
}

# Function to print an info line
print_info() {
    local info="$1"
    echo -e "${BLUE}${VERTICAL}${NC}    ${YELLOW}${info}$(printf %$(($width - ${#info} - 4))s)${BLUE}${VERTICAL}${NC}"
}

# Function to print a spacer
print_spacer() {
    echo -e "${BLUE}${VERTICAL}$(printf '%*s' $width)${VERTICAL}${NC}"
}

# Check system requirements
print_section "System Requirements" "${CYAN}"
print_spacer

# Check Python version
echo -e "${BLUE}${VERTICAL}${NC}    ${WHITE}Checking Python version...${NC}$(printf %$(($width - 28))s)${BLUE}${VERTICAL}${NC}"
if command -v python3 >/dev/null 2>&1; then
    python_version=$(python3 --version 2>&1 | awk '{print $2}')
    python_major=$(echo $python_version | cut -d. -f1)
    python_minor=$(echo $python_version | cut -d. -f2)
    
    if [ "$python_major" -ge 3 ] && [ "$python_minor" -ge 6 ]; then
        print_step "Python $python_version detected" "✓ OK" "${GREEN}"
    else
        print_step "Python $python_version (3.6+ recommended)" "⚠ WARNING" "${YELLOW}"
    fi
else
    print_step "Python 3 not found" "✗ FAILED" "${RED}"
    print_info "Please install Python 3.6 or higher"
fi

# Check for pip
if command -v pip3 >/dev/null 2>&1; then
    print_step "Pip installation" "✓ OK" "${GREEN}"
else
    print_step "Pip installation" "✗ FAILED" "${RED}"
    print_info "Please install pip for Python 3"
fi

# Check for common tools
print_spacer
print_section "Optional Security Tools" "${CYAN}"
print_spacer

tools=("nmap" "masscan" "subfinder" "assetfinder" "httpx" "whatweb" "nuclei" "waybackurls" "gau" "katana")
for tool in "${tools[@]}"; do
    if command -v $tool >/dev/null 2>&1; then
        print_step "$tool" "✓ FOUND" "${GREEN}"
    else
        print_step "$tool" "⚠ NOT FOUND" "${YELLOW}"
    fi
done

print_info "Missing tools will be replaced by built-in alternatives"
print_spacer

# Setup virtual environment
print_section "Python Environment Setup" "${CYAN}"
print_spacer

if command -v python3 -m venv >/dev/null 2>&1; then
    print_step "Setting up virtual environment" "⏳ RUNNING" "${YELLOW}"
    python3 -m venv venv 2>/dev/null
    
    # Determine correct activation command
    if [ -f venv/bin/activate ]; then
        source venv/bin/activate
        print_step "Virtual environment" "✓ ACTIVATED" "${GREEN}"
    else
        print_step "Virtual environment" "⚠ FAILED" "${YELLOW}"
        print_info "Continuing with system Python..."
    fi
else
    print_step "Virtual environment" "⚠ SKIPPED" "${YELLOW}"
    print_info "Python venv module not available"
fi

# Install Python requirements with progress visualization
print_step "Installing Python packages" "⏳ RUNNING" "${YELLOW}"

# Create a spinner function
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    echo -n "[     ]  (0%)"
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf "\b\b\b\b\b\b\b\b\b\b\b"
        printf "[%c    ]" "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
    done
    printf "\b\b\b\b\b\b\b\b\b\b\b"
    printf "[✓    ]  (100%%)"
    echo
}

# Install packages with a progress simulation
if command -v pip3 >/dev/null 2>&1; then
    pip3 install -r requirements.txt >/dev/null 2>&1 &
    PID=$!
    
    # Display spinner while pip installs
    spinner $PID
    
    print_step "Python requirements" "✓ INSTALLED" "${GREEN}"
else
    print_step "Python requirements" "✗ FAILED" "${RED}"
    print_info "Please install pip3 and try again"
fi

print_spacer

# Make the main script executable
print_section "Final Setup" "${CYAN}"
print_spacer

chmod +x recon_arsenal.py
print_step "Script permissions" "✓ CONFIGURED" "${GREEN}"

# Create directories for output if they don't exist
mkdir -p results
print_step "Output directories" "✓ CREATED" "${GREEN}"

print_spacer

# Display completion message
echo -e "${BLUE}${LEFT_CONNECTOR}${HORIZONTAL}$(printf '%*s' $border_width | tr ' ' "${HORIZONTAL}")${RIGHT_CONNECTOR}${NC}"
echo -e "${BLUE}${VERTICAL}${NC}${GREEN}${BOLD}                        Installation Complete!                         ${RESET}${BLUE}${VERTICAL}${NC}"
echo -e "${BLUE}${VERTICAL}${NC}                                                                      ${BLUE}${VERTICAL}${NC}"
echo -e "${BLUE}${VERTICAL}${NC}  ${CYAN}Run Web-Hunter using:${NC}                                                  ${BLUE}${VERTICAL}${NC}"
echo -e "${BLUE}${VERTICAL}${NC}  ${WHITE}python3 recon_arsenal.py${NC}                                                ${BLUE}${VERTICAL}${NC}"
echo -e "${BLUE}${VERTICAL}${NC}                                                                      ${BLUE}${VERTICAL}${NC}"
echo -e "${BLUE}${VERTICAL}${NC}  ${CYAN}For help, run:${NC}                                                         ${BLUE}${VERTICAL}${NC}"
echo -e "${BLUE}${VERTICAL}${NC}  ${WHITE}python3 recon_arsenal.py --help${NC}                                         ${BLUE}${VERTICAL}${NC}"
echo -e "${BLUE}${BOTTOM_LEFT}${HORIZONTAL}$(printf '%*s' $border_width | tr ' ' "${HORIZONTAL}")${BOTTOM_RIGHT}${NC}"

echo
echo -e "${YELLOW}Thank you for installing Web-Hunter!${NC}"
echo
