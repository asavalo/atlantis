#!/bin/bash

# Update git submodules for CRS-multilang project
# Usage: ./update_submodules.sh <MULTILANG_ROOT>

# set -e  # Exit on any error
# set -x  # Print commands as they are executed

# Check if argument is provided
if [[ -z "$1" ]]; then
    echo "Error: MULTILANG_ROOT path is required"
    echo "Usage: $0 <MULTILANG_ROOT>"
    exit 1
fi

MULTILANG_ROOT="$1"

# Validate the provided path
if [[ ! -d "$MULTILANG_ROOT" ]]; then
    echo "Error: Directory does not exist: $MULTILANG_ROOT"
    exit 1
fi

if [[ ! -f "$MULTILANG_ROOT/run.py" || ! -d "$MULTILANG_ROOT/benchmarks" ]]; then
    echo "Error: Invalid MULTILANG_ROOT path: $MULTILANG_ROOT"
    echo "Directory must contain run.py and benchmarks/ subdirectory"
    exit 1
fi

echo "=== CRS-multilang Submodule Update ==="
echo "Target directory: $MULTILANG_ROOT"
pushd "$MULTILANG_ROOT"
echo "Current working directory: $(pwd)"
echo "Running: git pull origin main"
git pull origin main 

echo ""
echo "=== Submodule Configuration ==="
declare -A submodule_branches=(
  ["benchmarks"]="main"
  ["blob-gen/multilang-llm-agent"]="main"
#  ["function-tracer"]="crs-multilang"
#  ["libs/libCRS"]="oss-fuzz"
#  ["libs/libFDP"]="main"
#  ["libs/multilspy"]="main"
#  ["libs/z3.rs"]="master"
)

echo "Configured submodules:"
for path in "${!submodule_branches[@]}"; do
  branch="${submodule_branches[$path]}"
  echo "  - $path -> $branch"
done

echo ""
echo "=== Initializing Submodules ==="
echo "Running: git submodule update --init"
git submodule update --init
echo "✅ Submodule initialization complete"

echo ""
echo "=== Updating Individual Submodules ==="
for path in "${!submodule_branches[@]}"; do
  branch="${submodule_branches[$path]}"
  echo ""
  echo "📦 Processing submodule: $path (target branch: $branch)"
  
  if [ ! -f "$path/.git" ]; then
    echo "❌ $path is not initialized correctly. Skipping."
    continue
  fi

  echo "Entering directory: $path"
  (
    cd "$path"
    echo "Current directory: $(pwd)"
    
    echo "Fetching latest changes from origin/$branch..."
    git fetch origin "$branch"
    
    echo "Checking out branch: $branch"
    git checkout -B "$branch" "origin/$branch" || {
      echo "⚠️  Failed to checkout $branch in $path"
      exit 1
    }
    
    echo "Pulling latest changes..."
    git pull origin "$branch"
    
    echo "Current commit: $(git rev-parse HEAD)"
    echo "✅ Successfully updated $path to latest $branch"
  )
done

echo ""
echo "=== Submodule Update Complete ==="
echo "All configured submodules have been updated successfully"

popd
