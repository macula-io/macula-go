#!/usr/bin/env bash
# Builds libmacula, cabi as a C shared library, for one release platform into
# an output directory, and refuses a library that would not load where
# cabi/CONTRACT.md "Release artifacts" promises it does:
#
#   scripts/libmacula/build.sh <platform> <out dir>
#
# platform is linux-x64, linux-arm64, macos-x64, macos-arm64 or windows-x64.
# The Linux builds run inside the manylinux_2_28 image of their architecture
# (the workflow runs this script there), and no GLIBC_ symbol version above
# 2.28 may appear. The macOS builds target macOS 12.0, which vtool must
# report as the library's minos. Run from the repository root with a Go
# toolchain on PATH.
set -euo pipefail

platform=$1
out=$2
glibc_floor=2.28
macos_floor=12.0

mkdir -p "$out"
export CGO_ENABLED=1

case "$platform" in
  linux-x64 | linux-arm64)
    file="libmacula-$platform.so"
    ;;
  macos-x64)
    file="libmacula-$platform.dylib"
    export GOOS=darwin GOARCH=amd64 CC="clang -arch x86_64" MACOSX_DEPLOYMENT_TARGET=$macos_floor
    ;;
  macos-arm64)
    file="libmacula-$platform.dylib"
    export GOOS=darwin GOARCH=arm64 CC="clang -arch arm64" MACOSX_DEPLOYMENT_TARGET=$macos_floor
    ;;
  windows-x64)
    file="macula-$platform.dll"
    ;;
  *)
    echo "build.sh: unknown platform $platform" >&2
    exit 2
    ;;
esac

go build -buildmode=c-shared -trimpath -ldflags=-s -o "$out/$file" ./cabi
# cgo's own header is not released: cabi/macula.h is the contract.
rm -f "$out/${file%.*}.h"

case "$platform" in
  linux-*)
    newest=$(objdump -T "$out/$file" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -V | tail -n 1)
    if [ -z "$newest" ]; then
      echo "build.sh: $file names no GLIBC_ symbol version at all" >&2
      exit 1
    fi
    if [ "$(printf '%s\n%s\n' "$newest" "$glibc_floor" | sort -V | tail -n 1)" != "$glibc_floor" ]; then
      echo "build.sh: $file needs GLIBC_$newest, above the $glibc_floor floor" >&2
      exit 1
    fi
    echo "$file: newest glibc symbol GLIBC_$newest (floor $glibc_floor)"
    ;;
  macos-*)
    minos=$(vtool -show-build "$out/$file" | awk '$1 == "minos" { print $2 }')
    if [ "$minos" != "$macos_floor" ]; then
      echo "build.sh: $file has minos '$minos', not $macos_floor" >&2
      exit 1
    fi
    echo "$file: minos $minos"
    ;;
esac
echo "built $out/$file"
