#!/bin/bash

# Author: The-Sycorax (https://github.com/The-Sycorax)
# License: MIT
# Copyright (c) 2024-2025
#
# Overview:
# This bash script automates the setup required to run a QRDX node. It handles system
# package updates, configures environment variables, sets up SQLite database directory,
# sets up a Python virtual environment, installs the required Python dependencies, and
# initiates the QRDX node. This script ensures that all prerequisites for operating a
# QRDX node are met and properly configured according to the user's preference.

# Parse command-line arguments for skipping prompts
SKIP_APT_INSTALL=false
SKIP_PROMPTS=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --skip-prompts) SKIP_PROMPTS=true ;;
        --skip-package-install) SKIP_APT_INSTALL=true ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

echo "Starting QRDX node setup..."
echo ""

# Global variables for node config
QRDX_DATABASE_PATH="${QRDX_DATABASE_PATH:-data/qrdx.db}"
QRDX_NODE_HOST="127.0.0.1"
QRDX_NODE_PORT="3006"
QRDX_SELF_URL=""
QRDX_BOOTSTRAP_NODE="https://node.qrdx.network"
LOG_LEVEL="INFO"
LOG_CONSOLE_HIGHLIGHTING="True"

USE_DEFAULT_ENV_VARS=false
env_file=".env"

# Virtual environment directory
VENV_DIR="venv"

update_and_install_packages() {
    echo "Updating package lists..."
    sudo apt update
    echo ""

    echo "Checking required system packages..."
    local packages_to_install=()
    local packages=("gcc" "libgmp-dev" "python3" "python3-dev" "python3-venv")

    for package in "${packages[@]}"; do
        if ! dpkg-query -W -f='${Status}' $package 2>/dev/null | grep -q "install ok installed"; then
            echo "Package $package is not installed."
            packages_to_install+=($package)
        else
            echo "Package $package is already installed."
        fi
    done

    if [ ${#packages_to_install[@]} -gt 0 ]; then
        if $SKIP_PROMPTS; then
            echo "Installing required packages: ${packages_to_install[*]}"
            echo ""
            sudo apt install -y ${packages_to_install[@]} || { echo ""; echo "Installation failed"; exit 1; }
        else
            echo ""
            sudo apt install ${packages_to_install[@]} || { echo ""; echo "Installation failed"; exit 1; }
        fi
        echo ""
        echo "Package installation complete."
    fi
}

# Function to validate the port number input
validate_port_input() {
    local prompt="$1"
    local var_name="$2"
    local input_port=""

    while true; do
        read -p "$prompt " input_port
        if [[ -z "$input_port" ]]; then
            input_port="3006"
            break
        elif ! [[ "$input_port" =~ ^[0-9]+$ ]]; then
            echo "Invalid input. Port must be a number."
            echo ""
        elif (( input_port < 1 || input_port > 65535 )); then
            echo "Invalid port number. Port must be between 1 and 65535."
            echo ""
        else
            break
        fi
    done
    eval $var_name="'$input_port'"
}

# Function to load existing .env variables into global variables
load_env_variables() {
    if [[ -f "$env_file" ]]; then
        while IFS='=' read -r key value; do
            if [[ $key == QRDX_DATABASE_PATH || $key == QRDX_NODE_HOST || $key == QRDX_NODE_PORT || $key == QRDX_SELF_URL || $key == QRDX_BOOTSTRAP_NODE || $key == LOG_LEVEL || $key == LOG_CONSOLE_HIGHLIGHTING ]]; then
                eval $key="'$value'"
            fi
        done < "$env_file"
    fi
}

# Function to identify missing or incomplete configuration variables
identify_missing_variables() {
    local env_file="$1"
    local missing_vars=()

    grep -qE "^QRDX_DATABASE_PATH=.+" "$env_file" || missing_vars+=("QRDX_DATABASE_PATH")
    grep -qE "^QRDX_NODE_HOST=.+" "$env_file" || missing_vars+=("QRDX_NODE_HOST")
    grep -qE "^QRDX_NODE_PORT=.+" "$env_file" || missing_vars+=("QRDX_NODE_PORT")
    grep -qE "^QRDX_SELF_URL=.+" "$env_file" || missing_vars+=("QRDX_SELF_URL")
    grep -qE "^QRDX_BOOTSTRAP_NODE=.+" "$env_file" || missing_vars+=("QRDX_BOOTSTRAP_NODE")
    grep -qE "^LOG_LEVEL=.+" "$env_file" || missing_vars+=("LOG_LEVEL")
    grep -qE "^LOG_CONSOLE_HIGHLIGHTING=.+" "$env_file" || missing_vars+=("LOG_CONSOLE_HIGHLIGHTING")
    echo "${missing_vars[@]}"
}

# Function to update or append a variable in the .env file
update_variable() {
    local prompt="$1"
    local var_name="$2"
    local env_file=".env"

    local default_value="${!var_name}"
    local current_value=$(grep "^$var_name=" "$env_file" 2>/dev/null | cut -d'=' -f2-)

    if ! $SKIP_PROMPTS && ! $USE_DEFAULT_ENV_VARS; then
        if [[ "$var_name" == "QRDX_NODE_PORT" ]]; then
            validate_port_input "$prompt (default: $default_value):" "$var_name"
        else
            read -p "$prompt (default: $default_value): " value
            if [[ -z "$value" ]]; then
                value="$default_value"
            fi
            eval $var_name="'$value'"
        fi
    elif [[ -z "$current_value" ]]; then
        eval $var_name="'$default_value'"
    fi

    if grep -q "^$var_name=" "$env_file" 2>/dev/null; then
        sed -i "s/^$var_name=.*/$var_name='${!var_name}'/" "$env_file"
    else
        echo "$var_name='${!var_name}'" >> "$env_file"
    fi
}

# Main function to set variables in a .env file
set_env_variables() {
    echo ""
    echo "Starting dotenv configuration..."
    echo ""
    local env_file=".env"

    if [[ -f "$env_file" ]]; then
        echo "$env_file file already exists."
        echo ""

        local missing_vars=($(identify_missing_variables "$env_file"))
        if [ ${#missing_vars[@]} -eq 0 ]; then
            if ! $SKIP_PROMPTS; then
                while true; do
                    read -p "Do you want to update the current configuration? (y/n): " update_choice
                    case "$update_choice" in
                        [Yy] )
                            missing_vars=("QRDX_DATABASE_PATH" "QRDX_NODE_HOST" "QRDX_NODE_PORT" "QRDX_SELF_URL" "QRDX_BOOTSTRAP_NODE" "LOG_LEVEL" "LOG_CONSOLE_HIGHLIGHTING")
                            echo "Leave blank to keep the current value."
                            echo ""
                            break;;
                        [Nn] )
                            echo "Keeping current configuration."
                            load_env_variables
                            return 0;;
                        * )
                            echo "Invalid input. Please enter 'y' or 'n'."; echo "";;
                    esac
                done
            else
                echo "Keeping current configuration."
                load_env_variables
                return 0
            fi
        else
            echo "The .env file is incomplete or has empty values."
            echo "Missing variables: ${missing_vars[*]}"
            echo ""
        fi
    else
        echo "$env_file file does not exist."
        echo "Proceeding with configuration..."
        echo ""
        > "$env_file"
        local missing_vars=($(identify_missing_variables "$env_file"))
    fi

    if ! $SKIP_PROMPTS; then
        while true; do
            read -p "Do you want to use the default values for configuration? (y/n): " use_defaults
            case "$use_defaults" in
                [Yy] )
                    USE_DEFAULT_ENV_VARS=true
                    echo "Using default values for configuration."
                    break;;
                [Nn] )
                    USE_DEFAULT_ENV_VARS=false
                    echo "Leave blank to use the default value."
                    echo ""
                    break;;
                * )
                    echo "Invalid input. Please enter 'y' or 'n'."; echo "";;
            esac
        done
    else
        USE_DEFAULT_ENV_VARS=true
        echo "Using default values for configuration."
    fi

    [[ " ${missing_vars[*]} " =~ " QRDX_DATABASE_PATH " ]] && update_variable "Enter SQLite database path" "QRDX_DATABASE_PATH"
    [[ " ${missing_vars[*]} " =~ " QRDX_NODE_HOST " ]] && update_variable "Enter local QRDX node address or hostname" "QRDX_NODE_HOST"
    [[ " ${missing_vars[*]} " =~ " QRDX_NODE_PORT " ]] && update_variable "Enter local QRDX node port" "QRDX_NODE_PORT"
    [[ " ${missing_vars[*]} " =~ " QRDX_SELF_URL " ]] && update_variable "Enter the public address of this QRDX node (leave blank if private)" "QRDX_SELF_URL"
    [[ " ${missing_vars[*]} " =~ " QRDX_BOOTSTRAP_NODE " ]] && update_variable "Enter the address of a main QRDX node to sync with" "QRDX_BOOTSTRAP_NODE"
    [[ " ${missing_vars[*]} " =~ " LOG_LEVEL " ]] && update_variable "Enter the log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)" "LOG_LEVEL"
    [[ " ${missing_vars[*]} " =~ " LOG_CONSOLE_HIGHLIGHTING " ]] && update_variable "Enable log highlighting? (True/False)" "LOG_CONSOLE_HIGHLIGHTING"

    echo ""
    echo "$env_file file configured."
}

setup_database_directory() {
    echo ""
    echo "Setting up SQLite database directory..."
    local db_dir=$(dirname "$QRDX_DATABASE_PATH")
    if [ -n "$db_dir" ] && [ "$db_dir" != "." ]; then
        mkdir -p "$db_dir"
        echo "Database directory created: $db_dir"
    fi
    echo "SQLite database will be at: $QRDX_DATABASE_PATH"
    echo "Database directory setup complete."
    echo ""
}

# Skip apt package installation if --skip-package-install is specified
if $SKIP_APT_INSTALL; then
    echo "Skipping APT package installation..."
else
    update_and_install_packages
fi

set_env_variables
setup_database_directory

VENV_DIR="venv"
echo "Checking if Python virtual environment exists..."

setup_venv() {
    if [ ! -d "$VENV_DIR" ]; then
        echo "A virtual environment does not exist."
        echo ""
        if $SKIP_PROMPTS; then
            echo "Creating virtual environment in ./$VENV_DIR..."
            python3 -m venv $VENV_DIR
            source $VENV_DIR/bin/activate
            echo "Virtual environment created and activated."
        else
            echo "Creating a Python virtual environment is highly recommended."
            while true; do
                read -p "Do you want to create a Python virtual environment? (y/n): " create_venv
                case "$create_venv" in
                    [Yy] )
                        echo ""
                        echo "Creating virtual environment in ./$VENV_DIR..."
                        python3 -m venv $VENV_DIR
                        source $VENV_DIR/bin/activate
                        echo "Virtual environment created and activated."
                        break;;
                    [Nn] )
                        echo ""
                        echo "Skipped..."
                        break;;
                    * )
                        echo "Invalid input. Please enter 'y' or 'n'."
                        echo ""
                esac
            done
        fi
    else
        activate_venv
    fi
}

activate_venv() {
    if [[ -z "$VIRTUAL_ENV" ]]; then
        echo "Virtual environment already exists but is not active."
        if $SKIP_PROMPTS; then
            echo ""
            echo "Activating virtual environment..."
            source $VENV_DIR/bin/activate
        else
            while true; do
                read -p "Do you want to activate it? (y/n): " activate_venv
                case "$activate_venv" in
                    [Yy] )
                        source $VENV_DIR/bin/activate
                        echo ""
                        echo "Virtual environment activated."
                        break;;
                    [Nn] )
                        echo ""
                        echo "Skipped..."
                        break;;
                    * )
                        echo "Invalid input. Please enter 'y' or 'n'."
                        echo ""
                esac
            done
        fi
    else
        echo "Virtual environment already exists and is active."
    fi
}

pip_install() {
    echo ""
    echo "Checking required Python packages..."
    readarray -t missing_packages < <(python3 -c "
import pkg_resources
from pkg_resources import DistributionNotFound, VersionConflict

requirements = [str(r) for r in pkg_resources.parse_requirements(open('requirements-v3.txt'))]

missing = []
for req in requirements:
    try:
        pkg_resources.require(req)
    except (DistributionNotFound, VersionConflict):
        missing.append(req)

sep = '~'
packages = []
for m in missing:
    package_name = m.split(sep, 1)[0]
    packages.append(package_name)
packages = ', '.join(packages)
print(str(packages))
")

    if [ ${#missing_packages} -eq 0 ]; then
        echo "Required packages are already installed."
        return
    else
        echo -e "\nThe following packages from requirements-v3.txt are missing:\n${missing_packages}."
    fi

    if ! $SKIP_PROMPTS; then
        while true; do
            read -p "Do you want to install the missing Python packages? (y/n): " install_req
            case "$install_req" in
                [Yy] ) break;;
                [Nn] ) echo ""; echo "Cancelled..."; exit 1;;
                * ) echo "Invalid input. Please enter 'y' or 'n'."; echo ""; continue;;
            esac
        done
    fi

    if [[ -z "$VIRTUAL_ENV" ]]; then
        echo ""
        echo "Warning: You are not currently in a virtual environment!"
        while true; do
            read -p "Are you sure you want to continue? (y/n): " confirm_global_install
            case "$confirm_global_install" in
                [Yy] ) break;;
                [Nn] ) echo ""; echo "Cancelled..."; exit 1;;
                * ) echo "Invalid input. Please enter 'y' or 'n'."; echo ""; continue;;
            esac
        done
    fi
    echo ""
    echo "Installing required Python packages..."
    echo ""
    pip install -r requirements-v3.txt || { echo "Failed to install python packages."; exit 1; }
    echo ""
    echo "Python packages installed."
}

setup_venv
pip_install

echo ""
echo "Node setup complete!"
echo ""
echo "Ready to start the QRDX node."

start_node(){
    echo ""
    echo "Starting QRDX node on http://$QRDX_NODE_HOST:$QRDX_NODE_PORT..."
    echo "Press Ctrl+C to exit."
    echo ""
    python3 run_node.py || { echo "Failed to start QRDX Node"; exit 1; }
}

if $SKIP_PROMPTS; then
    start_node
else
    while true; do
        read -p "Do you want to start the QRDX node now? (y/n): " start_choice
        case "$start_choice" in
            [Yy] ) start_node; break;;
            [Nn] ) echo "Skipped..."; break;;
            * ) echo "Invalid input. Please enter 'y' or 'n'."; echo "";;
        esac
    done
fi

echo ""
echo "Script executed successfully."
