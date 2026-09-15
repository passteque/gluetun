# Building for 32 bit ARM (armhf)

## What was failing

```
 => ERROR [base  3/10] RUN apk --update add git g++ findutils
1.271 exec /bin/sh: exec format error
```

The `base` stage — the Go toolchain stage — is pinned to the *build* platform:

```dockerfile
FROM --platform=${BUILDPLATFORM} golang:${GO_VERSION}-alpine${GO_ALPINE_VERSION} AS base
```

`BUILDPLATFORM` is a built-in build argument that BuildKit fills in with the platform of the
machine running the build. The Dockerfile used to also declare it with a default:

```dockerfile
ARG BUILDPLATFORM=linux/amd64
```

A declared default **wins over the value BuildKit injects**, so every stage above was pinned to
`linux/amd64` regardless of where the build ran. Building natively on an armhf host therefore
pulled the amd64 `golang` image and the first `RUN` in it died with `exec format error`. The
declaration has been removed, so `BUILDPLATFORM` is now the real build platform again.

## Platform naming

| You want | Docker platform | Alpine name | Typical hardware |
| --- | --- | --- | --- |
| armhf as Debian/Raspberry Pi OS 32 bit means it | `linux/arm/v7` | `armv7` | Pi 2/3/4/5 on a 32 bit OS |
| armhf as Alpine means it | `linux/arm/v6` | `armhf` | Pi 1, Pi Zero/Zero W |

## Building

Either use the helper script:

```sh
./build-armhf.sh                            # linux/arm/v7, loaded into the local docker
PLATFORM=linux/arm/v6 ./build-armhf.sh      # ARMv6
TAG=you/gluetun:armhf PUSH=1 ./build-armhf.sh
```

or call buildx directly:

```sh
docker buildx build --platform=linux/arm/v7 -t gluetun:armhf --load .
```

### Natively on the ARM host

Nothing else is needed: the Go toolchain runs on the host, the Go binary is built for the host,
and the final Alpine stage runs natively. It is just slow, and `go build` wants roughly 1 GB of
free RAM (add swap on a 1 GB Pi).

### Cross building from an x86 host

The Go part is a true cross compile and needs no emulation, but the final image stage runs
`apk add` for the target architecture, so the QEMU binfmt handlers must be registered on the
host once per boot:

```sh
docker run --privileged --rm tonistiigi/binfmt --install arm
```

Without it the build fails with the same `exec format error`, but in the *last* stage rather than
in `base`. `./build-armhf.sh --setup-qemu` does the registration for you, and the script refuses
to start a cross build when the handler is missing instead of failing halfway through.

`docker buildx build --platform=<other platform>` also requires a container driver builder;
the default `docker` driver cannot do it. The script creates a `gluetun-builder` for that.
