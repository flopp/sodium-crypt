#!/bin/bash

set -eu

P="HORSE-BATTERY-STAPLE"
T="$(mktemp -d)"

dd status=none if=/dev/urandom of="${T}/original" count=1 bs=1M

./sodium-crypt --encrypt "${P}" "${T}/original" "${T}/encrypted1"
./sodium-crypt --encrypt "${P}" "${T}/original" "${T}/encrypted2"

if cmp --quiet "${T}/encrypted1" "${T}/encrypted2" ; then
    echo "encrypting the same file twice resulted in equivalent files (=> same random salt!)"
    echo "=> ${T}"
    exit 1
fi

rm -rf "${T}"
