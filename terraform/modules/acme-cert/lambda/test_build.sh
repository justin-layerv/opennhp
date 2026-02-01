#!/bin/bash
# Verify the Lambda build package is complete and valid
#
# Run after build.sh to verify the package will work in Lambda.
# This script performs static checks without invoking AWS.
#
# Usage: bash test_build.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/../build/package"

echo "============================================"
echo "Verifying Lambda Build Package"
echo "============================================"
echo ""

ERRORS=0

# Check build directory exists
if [[ ! -d "${BUILD_DIR}" ]]; then
    echo "ERROR: Build directory does not exist: ${BUILD_DIR}"
    echo "Run build.sh first"
    exit 1
fi

# Check required Python packages
# Note: OpenSSL is the directory name created by pyOpenSSL package
echo "Checking required packages..."
REQUIRED_PACKAGES=(acme josepy cryptography dns OpenSSL cffi pycparser certifi)
for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if [[ -d "${BUILD_DIR}/${pkg}" ]] || [[ -f "${BUILD_DIR}/${pkg}.py" ]]; then
        echo "  [OK] ${pkg}"
    else
        echo "  [FAIL] ${pkg} - not found"
        ((ERRORS++))
    fi
done

# Check Lambda handler
echo ""
echo "Checking Lambda handler..."
if [[ -f "${BUILD_DIR}/acme_cert_manager.py" ]]; then
    echo "  [OK] acme_cert_manager.py exists"

    # Verify handler function exists
    if grep -q "def handler" "${BUILD_DIR}/acme_cert_manager.py"; then
        echo "  [OK] handler function found"
    else
        echo "  [FAIL] handler function not found"
        ((ERRORS++))
    fi
else
    echo "  [FAIL] acme_cert_manager.py not found"
    ((ERRORS++))
fi

# Check for Linux-compatible binaries
echo ""
echo "Checking platform compatibility..."
LINUX_SO=$(find "${BUILD_DIR}" -name "*x86_64-linux-gnu*.so" 2>/dev/null | head -1)
if [[ -n "${LINUX_SO}" ]]; then
    echo "  [OK] Linux x86_64 binaries found"
    echo "       Example: $(basename "${LINUX_SO}")"
else
    echo "  [WARN] No Linux x86_64 binaries found"
    echo "         Package may not work in Lambda if built on non-Linux"
fi

# Check for macOS binaries (should not be present)
MACOS_SO=$(find "${BUILD_DIR}" -name "*darwin*.so" 2>/dev/null | head -1)
if [[ -n "${MACOS_SO}" ]]; then
    echo "  [FAIL] macOS binaries found - will not work in Lambda"
    echo "         ${MACOS_SO}"
    ((ERRORS++))
fi

# Check package size
echo ""
echo "Checking package size..."
PACKAGE_SIZE_KB=$(du -sk "${BUILD_DIR}" | cut -f1)
PACKAGE_SIZE_MB=$((PACKAGE_SIZE_KB / 1024))
MAX_SIZE_MB=50  # Self-imposed limit (Lambda allows 250MB unzipped, 50MB zipped)

if [[ ${PACKAGE_SIZE_MB} -lt ${MAX_SIZE_MB} ]]; then
    echo "  [OK] Package size: ${PACKAGE_SIZE_MB}MB (limit: ${MAX_SIZE_MB}MB)"
else
    echo "  [FAIL] Package too large: ${PACKAGE_SIZE_MB}MB (limit: ${MAX_SIZE_MB}MB)"
    ((ERRORS++))
fi

# Try to syntax check the Python code
echo ""
echo "Checking Python syntax..."
if command -v python3 &>/dev/null; then
    if python3 -m py_compile "${BUILD_DIR}/acme_cert_manager.py" 2>/dev/null; then
        echo "  [OK] Python syntax valid"
    else
        echo "  [FAIL] Python syntax error in acme_cert_manager.py"
        ((ERRORS++))
    fi
else
    echo "  [SKIP] python3 not available"
fi

# Summary
echo ""
echo "============================================"
if [[ ${ERRORS} -eq 0 ]]; then
    echo "All checks passed!"
    echo "============================================"
    exit 0
else
    echo "FAILED: ${ERRORS} error(s) found"
    echo "============================================"
    exit 1
fi
