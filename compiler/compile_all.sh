#!/usr/bin/env bash
#

OPTS=""
FILES=""
# parse command line parameters.
for arg in "$@" ; do
	case "$arg" in
	-*) OPTS="$OPTS $arg" ;;
	*) FILES="$FILES $arg" ;;
	esac
done

for script in $FILES; do
	echo "Compiling script: $script"
	slua-compiler $OPTS $script
	#./slua-compiler $OPTS $script
done

