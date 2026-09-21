#!/bin/sh
# Build the gluetun image for 32 bit ARM (armhf).
#
# Usage:
#   ./build-armhf.sh                 # build linux/arm/v7, load into the local docker
#   PLATFORM=linux/arm/v6 ./build-armhf.sh
#   TAG=myrepo/gluetun:armhf PUSH=1 ./build-armhf.sh
#   ./build-armhf.sh --setup-qemu    # register the QEMU handlers first (cross build only)
#
# Notes:
# - linux/arm/v7 is what Debian/Raspberry Pi OS 32 bit calls armhf; Alpine calls it armv7.
#   Alpine's own "armhf" is ARMv6 (Pi 1 / Pi Zero): use PLATFORM=linux/arm/v6 for those.
# - Cross building from an x86 host needs the QEMU binfmt handlers, because the final
#   image stage runs `apk add` for the target architecture. Building natively on the ARM
#   host needs nothing extra.
set -eu

PLATFORM="${PLATFORM:-linux/arm/v7}"
TAG="${TAG:-gluetun:armhf}"
PUSH="${PUSH:-0}"

if [ "${1:-}" = "--setup-qemu" ]; then
  echo "==> Registering QEMU binfmt handlers (needs a privileged container)"
  docker run --privileged --rm tonistiigi/binfmt --install arm
  shift
fi

host_arch="$(uname -m)"
case "${host_arch}" in
  arm* | aarch64) native=1 ;;
  *) native=0 ;;
esac

if [ "${native}" = "0" ] && ! ls /proc/sys/fs/binfmt_misc/ 2>/dev/null | grep -q 'qemu-arm'; then
  echo "==> Host is ${host_arch} and no qemu-arm binfmt handler is registered."
  echo "    Cross building ${PLATFORM} will fail with 'exec format error' in the final stage."
  echo "    Run: ./build-armhf.sh --setup-qemu     (or: docker run --privileged --rm tonistiigi/binfmt --install arm)"
  exit 1
fi

# buildx is required for --platform; the default docker driver cannot build for
# another platform, so make sure a container driver builder exists.
if ! docker buildx inspect gluetun-builder >/dev/null 2>&1; then
  echo "==> Creating buildx builder 'gluetun-builder'"
  docker buildx create --name gluetun-builder --driver docker-container >/dev/null
fi

output="--load"
[ "${PUSH}" = "1" ] && output="--push"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo unknown)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
CREATED="${CREATED:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

echo "==> Building ${TAG} for ${PLATFORM} (version=${VERSION} commit=${COMMIT})"
exec docker buildx build \
  --builder gluetun-builder \
  --platform "${PLATFORM}" \
  --build-arg VERSION="${VERSION}" \
  --build-arg COMMIT="${COMMIT}" \
  --build-arg CREATED="${CREATED}" \
  --tag "${TAG}" \
  ${output} \
  "$@" \
  .
