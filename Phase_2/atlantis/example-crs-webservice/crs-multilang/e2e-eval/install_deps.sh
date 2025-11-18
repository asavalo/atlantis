#!/bin/bash

# Install dependencies and setup pyenv environment for CRS-multilang experiments
# Usage: ./install_deps.sh [MULTILANG_ROOT]

# set -e  # Exit on any error
# set -x  # Print commands as they are executed

PYENV_ENV_NAME="crs-e2e-experiments"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to find CRS-multilang directory by traversing up
find_crs_multilang_root() {
    local current_dir="$1"
    local max_levels=2
    local level=0
    
    while [[ $level -le $max_levels ]]; do
        if [[ -f "$current_dir/run.py" && -d "$current_dir/benchmarks" ]]; then
            echo "$current_dir"
            return 0
        fi
        current_dir="$(cd "$current_dir/.." && pwd)"
        level=$((level + 1))
    done
    
    return 1
}

# Accept MULTILANG_ROOT as first argument or auto-detect
if [[ -n "$1" ]]; then
    MULTILANG_ROOT="$1"
    echo "Using provided MULTILANG_ROOT: $MULTILANG_ROOT"
    
    # Validate provided path
    if [[ ! -f "$MULTILANG_ROOT/run.py" || ! -d "$MULTILANG_ROOT/benchmarks" ]]; then
        echo "Error: Invalid MULTILANG_ROOT path: $MULTILANG_ROOT"
        echo "Directory must contain run.py and benchmarks/ subdirectory"
        exit 1
    fi
else
    # Find CRS-multilang root directory automatically
    MULTILANG_ROOT=$(find_crs_multilang_root "$SCRIPT_DIR")
    
    if [[ -z "$MULTILANG_ROOT" ]]; then
        echo "Error: Could not find CRS-multilang directory"
        echo "Searched up to 2 levels from: $SCRIPT_DIR"
        echo "Looking for directory with run.py and benchmarks/ subdirectory"
        echo "You can also provide the path as first argument: $0 /path/to/multilang"
        exit 1
    fi
    echo "Auto-detected MULTILANG_ROOT: $MULTILANG_ROOT"
fi

echo "=== CRS-multilang Dependency Installation ==="
echo "Script directory: $SCRIPT_DIR"
echo "CRS-multilang root: $MULTILANG_ROOT"

echo ""
echo "=== Checking System Dependencies ==="

# Function to check if command exists
command_exists() {
    echo "Checking for $1..."
    if command -v "$1" >/dev/null 2>&1; then
        echo "✓ $1 is available"
        return 0
    else
        echo "✗ $1 is missing"
        return 1
    fi
}

# Check required tools
missing_tools=()

if ! command_exists tmux; then
    missing_tools+=("tmux")
fi

if ! command_exists rsync; then
    missing_tools+=("rsync")
fi

if ! command_exists pyenv; then
    missing_tools+=("pyenv")
fi

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo "Missing required dependencies:"
    for tool in "${missing_tools[@]}"; do
        echo "  - $tool"
    done
    echo ""
    echo "Installing missing dependencies on Ubuntu..."

    # Update package list
    echo "Updating package list..."
    sudo apt-get update -y

    # Install tmux and rsync if missing
    if [[ " ${missing_tools[*]} " =~ " tmux " ]]; then
        echo "Installing tmux..."
        sudo apt-get install -y -v tmux
        echo "✓ tmux installed successfully"
    fi

    if [[ " ${missing_tools[*]} " =~ " rsync " ]]; then
        echo "Installing rsync..."
        sudo apt-get install -y -v rsync
        echo "✓ rsync installed successfully"
    fi

    # Install pyenv if missing
    if [[ " ${missing_tools[*]} " =~ " pyenv " ]]; then
        echo "Installing pyenv dependencies..."
        sudo apt-get install -y -v make build-essential libssl-dev zlib1g-dev \
            libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm \
            libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev \
            libffi-dev liblzma-dev git
        echo "✓ pyenv dependencies installed"

        echo "Downloading and installing pyenv..."
        curl -L https://pyenv.run | bash
        echo "✓ pyenv download completed"

        # Add pyenv to PATH for current session
        export PYENV_ROOT="$HOME/.pyenv"
        export PATH="$PYENV_ROOT/bin:$PATH"
        eval "$(pyenv init -)"
        eval "$(pyenv virtualenv-init -)"

        echo "✓ pyenv installed and configured successfully"
    fi
fi

echo "✓ All required dependencies are available"

echo ""
echo "=== Setting up Python Environment ==="

# Check if environment already exists
if pyenv versions --bare | grep -q "^${PYENV_ENV_NAME}$"; then
    echo "✓ Environment $PYENV_ENV_NAME already exists"
else
    echo "Creating new pyenv environment: $PYENV_ENV_NAME"

    # Get current Python version
    python_version=$(python3 --version | cut -d' ' -f2)
    echo "Using Python version: $python_version"

    # Create virtualenv
    pyenv virtualenv "$python_version" "$PYENV_ENV_NAME"
    echo "✓ Created pyenv environment: $PYENV_ENV_NAME"
fi

# Install requirements
requirements_file="$SCRIPT_DIR/requirements.txt"
if [[ -f "$requirements_file" ]]; then
    echo "Installing requirements from $requirements_file"
    echo "Requirements file contents:"
    cat "$requirements_file"
    echo ""

    # Activate environment and install requirements
    echo "Activating pyenv environment: $PYENV_ENV_NAME"
    eval "$(pyenv init -)"
    pyenv activate "$PYENV_ENV_NAME"
    
    echo "Installing Python packages with verbose output..."
    pip install -v -r "$requirements_file"

    echo "✓ Requirements installed successfully"
    echo "Installed packages:"
    pip list
else
    echo "Warning: Requirements file not found: $requirements_file"
fi

echo ""
echo "=== Setup Complete ==="
echo "Environment '$PYENV_ENV_NAME' is ready for use"
echo ""
echo "To run experiments:"
echo "  pyenv activate $PYENV_ENV_NAME"
echo "  python run_eval.py --out-dir ./eval_out --copy-workdir --cleanup-temps --start-other-services"
