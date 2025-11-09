#!/usr/bin/env bash
# Safe static-only Windows PE analysis toolkit.
# Writes all outputs into ./ae_output/<target>/<timestamp>/
# Single-responsibility functions, small and testable.
set -euo pipefail
IFS=$'\n\t'

# Print usage and exit
usage() {
    cat <<'USAGE'
Usage: ./windows_static_analysis_tool.sh <target-file-or-dir>
Runs read-only static commands (file, hashes, strings,
radare2/rabin2/rizin, binwalk, yara, openssl) and saves
results. Does NOT execute samples.
USAGE
}

# Ensure required tools are available (warn if missing)
check_prereqs() {
    local -a tools=(file sha256sum md5sum strings binwalk
                    rizin r2 rabin2 yara openssl)
    for t in "${tools[@]}"; do
        if ! command -v "$t" >/dev/null 2>&1; then
            printf "WARN: %s not found\n" "$t"
        fi
    done
}

# Create an output directory for this run and target
init_output_dir() {
    local target=$1; local ts; ts=$(date -u +%Y%m%dT%H%M%SZ)
    OUTDIR="ae_output/$(basename "$target")/$ts"
    mkdir -p "$OUTDIR"
    printf "%s\n" "$OUTDIR"
}

# Compute file metadata and hashes
run_file_hashes() {
    local f=$1
    file "$f" >"$OUTDIR/file.txt" 2>&1 || true
    sha256sum "$f" >"$OUTDIR/sha256.txt" 2>&1 || true
    md5sum "$f" >"$OUTDIR/md5.txt" 2>&1 || true
    stat -c '%n %s %y' "$f" >"$OUTDIR/stat.txt" 2>&1 || true
}

# Extract readable strings (ascii + wide) safely
extract_strings() {
    local f=$1
    strings -a -n 8 "$f" >"$OUTDIR/strings_ascii.txt" 2>&1 || true
    strings -a -n 4 -e l "$f" >"$OUTDIR/strings_wide.txt" 2>&1 || true
}

# Run rizin/rabin2/radare2 one-liners and save outputs
run_pe_info() {
    local f=$1
    if command -v rizin >/dev/null 2>&1; then
        rizin -q -c "iI; iS; ii; iR; iV; q" "$f" >"$OUTDIR/rizin_info.txt" 2>&1 || true
    fi
    if command -v rabin2 >/dev/null 2>&1; then
        rabin2 -I "$f" >"$OUTDIR/rabin2_info.txt" 2>&1 || true
        rabin2 -zz "$f" >"$OUTDIR/rabin2_strings.txt" 2>&1 || true
    fi
    if command -v r2 >/dev/null 2>&1; then
        r2 -q -c "iI; iS; ii; iR; iV; q" "$f" >"$OUTDIR/r2_info.txt" 2>&1 || true
    fi
}

# Run binwalk to carve embedded data and record findings
run_binwalk() {
    local f=$1
    if command -v binwalk >/dev/null 2>&1; then
        binwalk -e "$f" --run-as=root --directory="$OUTDIR/binwalk_extracted" >"$OUTDIR/binwalk.txt" 2>&1 || true
    fi
}

# Attempt to locate and dump certs/PE resources using openssl
extract_cert_info() {
    local f=$1
    # try to find DER/PEM blobs in strings output
    grep -n -E "BEGIN.*PRIVATE KEY|BEGIN CERT|BEGIN RSA" "$OUTDIR/strings_ascii.txt" || true
    # try to dump any .der extracted by binwalk
    if [ -d "$OUTDIR/binwalk_extracted" ]; then
        find "$OUTDIR/binwalk_extracted" -type f \( -iname "*.der" -o -iname "*.cer" \) -print \|
          while read -r cert; do
            printf "== %s ==\n" "$cert" >"$OUTDIR/cert_${cert##*/}.txt"
            openssl x509 -in "$cert" -inform DER -noout -issuer -subject -serial -fingerprint -dates \ 
              >>"$OUTDIR/cert_${cert##*/}.txt" 2>&1 || true
        done
    fi
}

# Safe assembly of .part files (read-only copy then hash)
assemble_parts() {
    local dir=$1
    shopt -s nullglob
    local parts=("$dir"/*.part*)
    if (( ${#parts[@]} )); then
        local out="$OUTDIR/assembled.bin"
        cat "$dir"/*.part* >"$out" || true
        sha256sum "$out" >"$OUTDIR/assembled.sha256" 2>&1 || true
    fi
}

# Generate a lightweight report summarising findings
generate_report() {
    printf "Static analysis summary:\n" >"$OUTDIR/report.txt"
    printf "Hashes:\n" >>"$OUTDIR/report.txt"
    head -n 3 "$OUTDIR/sha256.txt" >>"$OUTDIR/report.txt" 2>&1 || true
    printf "Top strings (first 50 lines):\n" >>"$OUTDIR/report.txt"
    head -n 50 "$OUTDIR/strings_ascii.txt" >>"$OUTDIR/report.txt" 2>&1 || true
}

# Main driver: accepts file or directory and runs all modules
main() {
    if [ "$#" -ne 1 ]; then
        usage; exit 2
    fi
    local target=$1
    check_prereqs
    OUTDIR=$(init_output_dir "$target")
    if [ -d "$target" ]; then
        find "$target" -maxdepth 1 -type f -print | while read -r f; do
            run_file_hashes "$f"
            extract_strings "$f"
            run_pe_info "$f"
            run_binwalk "$f"
            extract_cert_info "$f"
            assemble_parts "$(dirname "$f")"
            generate_report
        done
    else
        run_file_hashes "$target"
        extract_strings "$target"
        run_pe_info "$target"
        run_binwalk "$target"
        extract_cert_info "$target"
        assemble_parts "$(dirname "$target")"
        generate_report
    fi
    printf "Results saved to: %s\n" "$OUTDIR"
}

main "$@"

