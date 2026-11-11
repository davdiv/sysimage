#!/bin/bash
#
# veritytab-apply.sh — read a veritytab produced by sysimage and run the
# corresponding `veritysetup` command for each entry.
#
# A veritytab line has the form:
#
#   <volume> <data_device> <hash_device> <root_hash> <options>
#
# where <options> is a comma-separated list of key=value pairs such as
# `format=1,hash=sha256,data-blocks=300,hash-offset=...,salt=...`.
#
# Each entry is turned into:
#
#   veritysetup open <data_device> <volume> <hash_device> <root_hash> \
#       --format=1 --hash=sha256 --data-blocks=...
#
# Usage:
#   veritytab-apply.sh [-n|--dry-run] [-c|--close] [-v|--verbose] <veritytab>
#
# Options:
#   -n, --dry-run   Print the commands that would be run without executing them.
#   -c, --close     Close each volume (veritysetup close <volume>) instead of
#                   opening it. Useful for tearing down an applied veritytab.
#   -v, --verbose   Print every command before running it (implies dry-run output
#                   prefix is shown even on real execution).
#   -h, --help      Show this help.
#
# The script returns a non-zero status if any veritysetup invocation fails,
# but continues to attempt the remaining entries so that a partial teardown
# is still possible.

set -u

dry_run=0
close=0
verbose=0
veritytab=""

usage() {
    # Print the leading comment block (the header documentation) as help text.
    sed -n '3,31p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -n|--dry-run) dry_run=1 ;;
        -c|--close)   close=1 ;;
        -v|--verbose)  verbose=1 ;;
        -h|--help)     usage 0 ;;
        --)            shift; break ;;
        -*)           echo "veritytab-apply: unknown option: $1" >&2; usage 1 ;;
        *)            break ;;
    esac
    shift
done

if [ $# -lt 1 ]; then
    echo "veritytab-apply: missing veritytab argument" >&2
    usage 1
fi
veritytab="$1"
shift

if [ ! -f "$veritytab" ]; then
    echo "veritytab-apply: file not found: $veritytab" >&2
    exit 1
fi

# Convert the comma-separated veritytab options string into veritysetup
# `--key=value` arguments. Each option may use either `=` or `:` as the
# separator (veritytab allows both); we normalise to `=`.
options_to_flags() {
    local opts="$1"
    [ -z "$opts" ] && return 0
    # Save and restore IFS so word splitting only happens on commas.
    local IFS=','
    local kv key value
    for kv in $opts; do
        # Normalise the first ':' separator to '=' (veritysetup uses '=').
        kv="${kv/:/=}"
        key="${kv%%=*}"
        value="${kv#*=}"
        if [ "$key" = "$value" ]; then
            # Bare flag with no value.
            printf '%s\n' "--$key"
        else
            printf '%s\n' "--$key=$value"
        fi
    done
}

run_cmd() {
    if [ "$verbose" = 1 ] || [ "$dry_run" = 1 ]; then
        printf '+ %s\n' "$*"
    fi
    if [ "$dry_run" = 1 ]; then
        return 0
    fi
    "$@"
}

rc=0
linenum=0
while IFS= read -r line || [ -n "$line" ]; do
    linenum=$((linenum + 1))
    # Strip leading whitespace for comment/blank detection.
    trimmed="${line#"${line%%[![:space:]]*}"}"
    case "$trimmed" in
        ''|'#'*) continue ;;
    esac

    # Split into fields on whitespace. The fifth field is the options list and
    # must not itself contain whitespace (sysimage never emits any there).
    set -- $line
    volume="$1"
    data_device="$2"
    hash_device="$3"
    root_hash="$4"
    opts="${5:-}"

    if [ -z "$volume" ] || [ -z "$data_device" ] || [ -z "$hash_device" ] || [ -z "$root_hash" ]; then
        echo "veritytab-apply: $veritytab:$linenum: malformed line (need at least volume data hash root_hash): $line" >&2
        rc=1
        continue
    fi

    if [ "$close" = 1 ]; then
        run_cmd veritysetup close "$volume" || rc=1
        continue
    fi

    # Build the argument list: veritysetup open <data> <volume> <hash> <root> [flags...]
    mapfile -t flags < <(options_to_flags "$opts")
    if [ "$dry_run" = 1 ] || [ "$verbose" = 1 ]; then
        printf '+ veritysetup open %s %s %s %s' \
            "$data_device" "$volume" "$hash_device" "$root_hash"
        if [ "${#flags[@]}" -gt 0 ]; then
            printf ' \\\n'
            local_first=1
            for f in "${flags[@]}"; do
                if [ "$local_first" = 1 ]; then
                    printf '    %s' "$f"
                    local_first=0
                else
                    printf ' %s' "$f"
                fi
            done
        fi
        printf '\n'
    fi
    if [ "$dry_run" = 1 ]; then
        continue
    fi
    if ! veritysetup open "$data_device" "$volume" "$hash_device" "$root_hash" "${flags[@]}"; then
        rc=1
    fi
done < "$veritytab"

exit "$rc"