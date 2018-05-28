#!/bin/bash
set -eu
source ../common/package-build-helpers.sh

importgo
upstream "rktlet-v${VERSION}.tar.xz"
exportorig "homeworld-rktlet-${VERSION}.tar.xz"
build
