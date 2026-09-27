#!/usr/bin/env bash
# Copyright 2026 libsignal-go contributors.
# SPDX-License-Identifier: AGPL-3.0-only
#
# Runs every native Go fuzz target in the module for a short budget each.
#
# Usage: scripts/fuzz.sh [package pattern ...]   (default: ./...)
#
# Environment:
#   FUZZTIME     budget per target, as for go test -fuzztime (default 10s)
#   FUZZ_FILTER  only run targets whose "pkg.FuzzName" matches this ERE
#                (pkg relative to the module, e.g. "spqr.FuzzRecv")
#   FUZZ_SHARD   "i/n": run only every n-th target, starting at index i
#                (0-based), so CI can split the targets over n jobs
#   FUZZ_ARTIFACT_DIR  if set, new corpus entries (the reproducers of failing
#                targets) are also copied there, keeping their paths
#
# Seed corpora already run as ordinary unit tests under `go test ./...`; this
# script adds the mutation phase. A failing target leaves its reproducer in
# <pkg>/testdata/fuzz/<FuzzName>/; the script lists every such file at the end
# and exits non-zero once all targets have run. See docs/fuzzing.md.
set -euo pipefail

cd "$(dirname "$0")/.."

fuzztime="${FUZZTIME:-10s}"
filter="${FUZZ_FILTER:-}"
shard="${FUZZ_SHARD:-0/1}"
shard_index="${shard%/*}"
shard_count="${shard#*/}"
if ! [[ "$shard_index" =~ ^[0-9]+$ && "$shard_count" =~ ^[1-9][0-9]*$ ]] || [ "$shard_index" -ge "$shard_count" ]; then
	echo "FUZZ_SHARD must be i/n with 0 <= i < n, got '$shard'" >&2
	exit 2
fi
module="$(go list -m)"
if [ "$#" -eq 0 ]; then
	set -- ./...
fi

# Remember which corpus files exist before the run, so new crashers stand out.
before="$(mktemp)"
find . -path ./.git -prune -o -path '*/testdata/fuzz/*' -type f -print | sort >"$before"

log="$(mktemp)"
trap 'rm -f "$before" "$log"' EXIT

# run_target fuzzes one target. Go's fuzzer can fail with "context deadline
# exceeded" and no reproducer when -fuzztime runs out while it is minimizing
# an input; that is retried once, not reported as a crash.
run_target() {
	local pkg="$1" name="$2" attempt
	for attempt in 1 2; do
		if go test -run '^$' -fuzz "^${name}\$" -fuzztime "$fuzztime" "$pkg" 2>&1 | tee "$log"; then
			return 0
		fi
		if grep -q 'context deadline exceeded' "$log" && ! grep -q 'Failing input written to' "$log" && [ "$attempt" -eq 1 ]; then
			echo "fuzz.sh: $pkg $name hit the fuzztime deadline while minimizing; retrying once" >&2
			continue
		fi
		return 1
	done
	return 1
}

targets=0
seen=0
failed=()
for pkg in $(go list "$@"); do
	dir="$(go list -f '{{.Dir}}' "$pkg")"
	# Skip packages without test files quickly.
	if ! compgen -G "$dir/*_test.go" >/dev/null; then
		continue
	fi
	list="$(go test -list '^Fuzz' "$pkg")"
	names="$(grep '^Fuzz' <<<"$list" || true)"
	for name in $names; do
		if [ -n "$filter" ] && ! [[ "${pkg#"$module"/}.$name" =~ $filter ]]; then
			continue
		fi
		seen=$((seen + 1))
		if [ $(((seen - 1) % shard_count)) -ne "$shard_index" ]; then
			continue
		fi
		targets=$((targets + 1))
		echo "::group::$pkg $name ($fuzztime)"
		if ! run_target "$pkg" "$name"; then
			failed+=("$pkg $name")
		fi
		echo "::endgroup::"
	done
done

echo "ran $targets of $seen fuzz targets (shard $shard) for $fuzztime each"
if [ "${#failed[@]}" -gt 0 ]; then
	echo "failed targets:"
	printf '  %s\n' "${failed[@]}"
	echo "new corpus entries (reproducers):"
	find . -path ./.git -prune -o -path '*/testdata/fuzz/*' -type f -print | sort | comm -13 "$before" - |
		while read -r entry; do
			echo "  $entry"
			if [ -n "${FUZZ_ARTIFACT_DIR:-}" ]; then
				mkdir -p "$FUZZ_ARTIFACT_DIR/$(dirname "$entry")"
				cp "$entry" "$FUZZ_ARTIFACT_DIR/$entry"
			fi
		done
	exit 1
fi
