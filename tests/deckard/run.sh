#!/usr/bin/env bash
# Run Deckard's resolver scenarios against tdns-imr. See README.md.
#
#   DECKARD=/path/to/deckard TDNS_IMR=/path/to/tdns-imr ./run.sh [pytest args...]
#
# SET chooses the scenarios, all of them minus skip.txt:
#   clock-free  (default) those with no trust anchor and no TIME_PASSES, which
#               need no fake clock
#   all         every scenario
#   <file.rpl>  one scenario, by name, skip list ignored
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
: "${DECKARD:?set DECKARD to a Deckard checkout}"
: "${TDNS_IMR:?set TDNS_IMR to the tdns-imr binary}"
set_name=${SET:-clock-free}

[ "$(uname -s)" = Linux ] || { echo "Deckard runs on Linux only"; exit 1; }
[ -x "$TDNS_IMR" ] || { echo "not an executable: $TDNS_IMR"; exit 1; }
python3 -c 'import lief, augeas, pyroute2' 2>/dev/null ||
	{ echo "python3 lacks Deckard's modules; activate its venv first"; exit 1; }

pin=$(tr -d '[:space:]' < "$here/DECKARD_COMMIT")
have=$(git -C "$DECKARD" rev-parse HEAD)
case "$have" in
"$pin"*) ;;
*) echo "Deckard is at ${have:0:12}, want $pin: git -C $DECKARD checkout $pin"; exit 1 ;;
esac

# Deckard loads templates relative to its own directory.
ln -sfn "$here" "$DECKARD/tdns"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/set" "$work/bin"
ln -s "$(readlink -f "$TDNS_IMR")" "$work/bin/tdns-imr"

skipped() { grep -qE "^$1([[:space:]]|\$)" "$here/skip.txt"; }
needs_clock() {
	awk '/CONFIG_END/{exit} {print}' "$1" | grep -qiE '^[[:space:]]*trust-anchor[[:space:]]*:' ||
		grep -q 'TIME_PASSES' "$1"
}

n=0
case "$set_name" in
*.rpl)
	ln -s "$DECKARD/sets/resolver/$set_name" "$work/set/" && n=1 ;;
clock-free | all)
	for f in "$DECKARD"/sets/resolver/*.rpl; do
		b=$(basename "$f")
		skipped "$b" && continue
		[ "$set_name" = clock-free ] && needs_clock "$f" && continue
		ln -s "$f" "$work/set/"
		n=$((n + 1))
	done ;;
*) echo "unknown SET: $set_name"; exit 1 ;;
esac
echo "tdns-imr: $(readlink -f "$TDNS_IMR")"
echo "Deckard ${have:0:12}, set $set_name: $n scenarios"

export PATH="$work/bin:$PATH"
cd "$DECKARD"
./run.sh --config tdns/configs/tdns-imr.yaml --scenarios "$work/set" -rfE "$@"
