#!/bin/bash
# Build Lambda package with dependencies bundled
#
# This script installs Python dependencies and prepares the Lambda package.
# It must be run BEFORE terraform plan/apply (CI does this automatically).
#
# Requirements:
# - Python 3.12
# - pip
#
# Usage:
#   bash terraform/modules/acme-cert/lambda/build.sh
#
# The cryptography library has native extensions that require platform-specific
# wheels. This script downloads manylinux wheels for Lambda compatibility.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/../build/package"
REQUIREMENTS_FILE="${SCRIPT_DIR}/requirements.txt"

# Lambda runtime configuration - must match aws_lambda_function.cert_manager
PYTHON_VERSION="3.12"
PLATFORM="manylinux2014_x86_64"  # For x86_64 Lambda architecture

echo "============================================"
echo "Building ACME Certificate Manager Lambda"
echo "============================================"
echo "Build directory: ${BUILD_DIR}"
echo "Platform: ${PLATFORM}"
echo "Python: ${PYTHON_VERSION}"
echo ""

# Find pip command (pip3 or pip or python3 -m pip)
if command -v pip3 &>/dev/null; then
    PIP_CMD="pip3"
elif command -v pip &>/dev/null; then
    PIP_CMD="pip"
elif command -v python3 &>/dev/null; then
    PIP_CMD="python3 -m pip"
else
    echo "ERROR: pip not found. Install Python 3.12 with pip."
    exit 1
fi

echo "Using pip: ${PIP_CMD}"

# Verify pip version supports --platform
if ! ${PIP_CMD} install --help | grep -q -- "--platform"; then
    echo "ERROR: pip version too old. Upgrade pip: ${PIP_CMD} install --upgrade pip"
    exit 1
fi

# Clean previous build
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# Install dependencies for Lambda (x86_64 Linux)
# This downloads pre-built manylinux wheels that work in Lambda
echo ""
echo "Installing Python dependencies..."
if ! ${PIP_CMD} install \
    --target "${BUILD_DIR}" \
    --platform "${PLATFORM}" \
    --implementation cp \
    --python-version "${PYTHON_VERSION}" \
    --only-binary=:all: \
    --no-deps \
    -r "${REQUIREMENTS_FILE}"; then
    echo ""
    echo "ERROR: Failed to install platform-specific packages."
    echo "This usually means a package doesn't have pre-built wheels for ${PLATFORM}."
    echo ""
    echo "Options:"
    echo "  1. Use Docker to build: docker run --rm -v \$(pwd):/work -w /work python:3.12 bash build.sh"
    echo "  2. Check if all packages in requirements.txt have manylinux wheels"
    exit 1
fi

# Install dependencies (some packages need their dependencies too)
# This second pass allows pip to resolve transitive dependencies
echo ""
echo "Installing package dependencies..."
${PIP_CMD} install \
    --target "${BUILD_DIR}" \
    --platform "${PLATFORM}" \
    --implementation cp \
    --python-version "${PYTHON_VERSION}" \
    --only-binary=:all: \
    -r "${REQUIREMENTS_FILE}" 2>&1 | tee /tmp/pip-deps.log
# Check pip exit code (not tee's) using PIPESTATUS
if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
    echo ""
    echo "WARNING: Some transitive dependencies may have failed to install."
    echo "Check /tmp/pip-deps.log for details. Continuing with verification..."
fi

# Copy Lambda code
echo ""
echo "Copying Lambda handler..."
cp "${SCRIPT_DIR}/acme_cert_manager.py" "${BUILD_DIR}/"

# Clean up unnecessary files to reduce package size
echo "Cleaning up unnecessary files..."
find "${BUILD_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${BUILD_DIR}" -type d -name "*.dist-info" -exec rm -rf {} + 2>/dev/null || true
find "${BUILD_DIR}" -type d -name "tests" -exec rm -rf {} + 2>/dev/null || true
find "${BUILD_DIR}" -type f -name "*.pyc" -delete 2>/dev/null || true

# Verify critical packages are present
echo ""
echo "Verifying package contents..."
MISSING_PACKAGES=""
for pkg in acme josepy cryptography dns; do
    if [[ ! -d "${BUILD_DIR}/${pkg}" ]]; then
        MISSING_PACKAGES="${MISSING_PACKAGES} ${pkg}"
    fi
done

if [[ -n "${MISSING_PACKAGES}" ]]; then
    echo "ERROR: Missing required packages:${MISSING_PACKAGES}"
    echo "Build directory contents:"
    ls -la "${BUILD_DIR}"
    exit 1
fi

# Verify Lambda handler exists
if [[ ! -f "${BUILD_DIR}/acme_cert_manager.py" ]]; then
    echo "ERROR: Lambda handler not found in build directory"
    exit 1
fi

# Restore .gitkeep placeholder (for fresh clones to have directory structure)
cat > "${BUILD_DIR}/.gitkeep" << 'GITKEEP'
# Placeholder for Lambda package. Populated by lambda/build.sh
# This file ensures the directory exists for terraform plan.
GITKEEP

# Show package statistics
PACKAGE_SIZE=$(du -sh "${BUILD_DIR}" | cut -f1)
FILE_COUNT=$(find "${BUILD_DIR}" -type f | wc -l | tr -d ' ')
echo ""
echo "============================================"
echo "Build complete!"
echo "============================================"
echo "Package size: ${PACKAGE_SIZE}"
echo "File count: ${FILE_COUNT}"
echo "Location: ${BUILD_DIR}"
echo ""
echo "Contents:"
ls "${BUILD_DIR}" | head -20
