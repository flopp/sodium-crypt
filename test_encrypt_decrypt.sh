#!/bin/bash

set -eu

P="HORSE-BATTERY-STAPLE"
T="$(mktemp -d)"

dd status=none if=/dev/urandom of="${T}/original" count=1 bs=1M

./sodium-crypt --encrypt "${P}" "${T}/original"  "${T}/encrypted"
./sodium-crypt --decrypt "${P}" "${T}/encrypted" "${T}/decrypted"

if ! cmp --quiet "${T}/original" "${T}/decrypted" ; then
    echo "en/decryption round-trip did not result in an equivalent file"
    echo "=> ${T}"
    exit 1
fi

rm -rf "${T}"
