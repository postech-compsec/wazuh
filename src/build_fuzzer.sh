#!/usr/bin/env bash
set -euo pipefail

# Wrapper for reproducible fuzzing builds.
# Default flow: clean -> deps -> TARGET=fuzzer build.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

MODE="${FUZZ_MODE:-partial}"
TARGETS="${FUZZ_TARGETS:-fuzz-remoted}"
DO_CLEAN="${FUZZ_DO_CLEAN:-1}"
DO_DEPS="${FUZZ_DO_DEPS:-1}"
JOBS="${FUZZ_JOBS:-$(nproc)}"
VERBOSE="${FUZZ_VERBOSE:-0}"
LOG_FILE_DEFAULT="${SCRIPT_DIR}/fuzz-build-$(date +%Y%m%d-%H%M%S).log"
LOG_FILE="${FUZZ_LOG_FILE:-${LOG_FILE_DEFAULT}}"

usage() {
    cat <<'EOF'
Usage:
                ./build_fuzzer.sh [--mode partial|full] [--targets "fuzz-remoted fuzz-decode-event|all"] [--jobs N] [--log-file FILE] [--verbose] [--skip-clean] [--skip-deps]

Environment overrides:
  FUZZ_MODE=partial|full
    FUZZ_TARGETS="fuzz-remoted fuzz-decode-event|all"
  FUZZ_DO_CLEAN=0|1
  FUZZ_DO_DEPS=0|1
    FUZZ_JOBS=N
    FUZZ_VERBOSE=0|1
    FUZZ_LOG_FILE=/path/to/build.log

Examples:
  ./build_fuzzer.sh
  ./build_fuzzer.sh --mode full --targets "fuzz-remoted fuzz-decode-event"
                ./build_fuzzer.sh --mode full --targets "all"
    ./build_fuzzer.sh --mode full --targets "fuzz-remoted" --jobs 8
    ./build_fuzzer.sh --mode full --targets "fuzz-remoted" --verbose --log-file ./dump.log
  FUZZ_MODE=partial FUZZ_TARGETS="fuzz-remoted" ./build_fuzzer.sh
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --targets)
            TARGETS="$2"
            shift 2
            ;;
        --jobs)
            JOBS="$2"
            shift 2
            ;;
        --log-file)
            LOG_FILE="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        --skip-clean)
            DO_CLEAN=0
            shift
            ;;
        --skip-deps)
            DO_DEPS=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [[ "${MODE}" != "partial" && "${MODE}" != "full" ]]; then
    echo "Invalid mode: ${MODE}. Expected 'partial' or 'full'." >&2
    exit 1
fi

if ! [[ "${JOBS}" =~ ^[0-9]+$ ]] || [[ "${JOBS}" -lt 1 ]]; then
    echo "Invalid jobs value: ${JOBS}. Expected a positive integer." >&2
    exit 1
fi

if ! [[ "${VERBOSE}" =~ ^[01]$ ]]; then
    echo "Invalid verbose value: ${VERBOSE}. Expected 0 or 1." >&2
    exit 1
fi

if [[ "${TARGETS,,}" == "all" ]]; then
    SUPPORTED_TARGETS_RAW="$(make -s TARGET=fuzzer print-supported-fuzz-targets)"
    if [[ -z "${SUPPORTED_TARGETS_RAW}" ]]; then
        echo "Failed to read supported fuzz targets from Makefile." >&2
        exit 1
    fi
    TARGETS="${SUPPORTED_TARGETS_RAW}"
fi

mkdir -p "$(dirname "${LOG_FILE}")"

if [[ "${VERBOSE}" == "1" ]]; then
    MAKE_VERBOSE_FLAG="V=yes"
else
    MAKE_VERBOSE_FLAG=""
fi

exec > >(tee "${LOG_FILE}") 2>&1
echo "[fuzzer] log_file=${LOG_FILE}"

echo "[fuzzer] mode=${MODE}"
echo "[fuzzer] targets=${TARGETS}"
echo "[fuzzer] jobs=${JOBS}"
echo "[fuzzer] verbose=${VERBOSE}"

if [[ "${DO_CLEAN}" == "1" ]]; then
    echo "[fuzzer] make clean"
    make ${MAKE_VERBOSE_FLAG} clean
fi

if [[ "${DO_DEPS}" == "1" ]]; then
    echo "[fuzzer] make deps"
    make -j"${JOBS}" ${MAKE_VERBOSE_FLAG} deps
fi

echo "[fuzzer] make TARGET=fuzzer FUZZ_MODE=${MODE} FUZZ_TARGETS=${TARGETS} JOBS=${JOBS}"
make -j"${JOBS}" ${MAKE_VERBOSE_FLAG} TARGET=fuzzer FUZZ_MODE="${MODE}" FUZZ_TARGETS="${TARGETS}" JOBS="${JOBS}" build
