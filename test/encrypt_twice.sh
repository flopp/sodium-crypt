#!/bin/bash

set -eu

SODIUM_CRYPT="${1}"
PASSWORD="HORSE-BATTERY-STAPLE"
T="$(mktemp -d)"

dd status=none if=/dev/urandom of="${T}/original" count=1 bs=1M

"${SODIUM_CRYPT}" --encrypt "${PASSWORD}" "${T}/original" "${T}/encrypted1"
"${SODIUM_CRYPT}" --encrypt "${PASSWORD}" "${T}/original" "${T}/encrypted2"

if cmp --quiet "${T}/encrypted1" "${T}/encrypted2" ; then
    echo "encrypting the same file twice resulted in equivalent files (=> same random salt!)"
    echo "=> ${T}"
    exit 1
fi

rm -rf "${T}"
