#!/bin/bash

set -e

here=$(dirname $(realpath "$0" 2> /dev/null || grealpath "$0"))
. "$here"/base.sh || (echo "Could not source contrib/base.sh" && exit 1)

pkgname="mmr-accumulator"
info "Installing $pkgname..."

src="$here/$pkgname/python/mmr_accumulator/mmr_accumulator.py"
dst="$here/../electroncash/mmr_accumulator.py"

if ! [ -r "$src" ]; then
    fail "Source not found: $src. Did you initialize git submodules?"
fi

cp -fpv "$src" "$dst" || fail "Could not copy $pkgname to electroncash folder"

info "$pkgname has been placed in the 'electroncash' folder."
