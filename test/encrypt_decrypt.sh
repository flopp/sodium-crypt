#!/bin/bash

set -eu

SODIUM_CRYPT="${1}"
PASSWORD="HORSE-BATTERY-STAPLE"
T="$(mktemp -d)"

dd status=none if=/dev/urandom of="${T}/original" count=1 bs=1M

"${SODIUM_CRYPT}" --encrypt "${PASSWORD}" "${T}/original"  "${T}/encrypted"
"${SODIUM_CRYPT}" --decrypt "${PASSWORD}" "${T}/encrypted" "${T}/decrypted"

if ! cmp --quiet "${T}/original" "${T}/decrypted" ; then
    echo "en/decryption round-trip did not result in an equivalent file"
    echo "=> ${T}"
    exit 1
fi

rm -rf "${T}"
