# Gluetun VPN client

Lightweight swiss-army-knife-like VPN client to multiple VPN service providers

⚠️ This and [gluetun-wiki](https://github.com/qdm12/gluetun-wiki) are the only websites for Gluetun, other websites claiming to be official are scams ⚠️

🗯️ this repository will be migrated to [github.com/passteque/gluetun](https://github.com/passteque/gluetun) on 2026-05-21, which is a Github organization under my sole control, so don't get alarmed if you get redirected in the coming days 😉 Reason being migrating Github sponsors to the Open source collective due to my personal situation, basically annoying paperwork. On the plus side, it will be more transparent and funds donated will only be used for the project. The Docker image names will remain the same.

![Title image](https://raw.githubusercontent.com/passteque/gluetun/master/title.svg)

[![Build status](https://github.com/passteque/gluetun/actions/workflows/ci.yml/badge.svg)](https://github.com/passteque/gluetun/actions/workflows/ci.yml)

[![Docker pulls qmcgaw/gluetun](https://img.shields.io/docker/pulls/qmcgaw/gluetun.svg)](https://hub.docker.com/r/qmcgaw/gluetun)
[![Docker pulls qmcgaw/private-internet-access](https://img.shields.io/docker/pulls/qmcgaw/private-internet-access.svg)](https://hub.docker.com/r/qmcgaw/gluetun)

[![Docker stars qmcgaw/gluetun](https://img.shields.io/docker/stars/qmcgaw/gluetun.svg)](https://hub.docker.com/r/qmcgaw/gluetun)
[![Docker stars qmcgaw/private-internet-access](https://img.shields.io/docker/stars/qmcgaw/private-internet-access.svg)](https://hub.docker.com/r/qmcgaw/gluetun)

![Last release](https://img.shields.io/github/release/passteque/gluetun?label=Last%20release)
![Last Docker tag](https://img.shields.io/docker/v/qmcgaw/gluetun?sort=semver&label=Last%20Docker%20tag)
[![Last release size](https://img.shields.io/docker/image-size/qmcgaw/gluetun?sort=semver&label=Last%20released%20image)](https://hub.docker.com/r/qmcgaw/gluetun/tags?page=1&ordering=last_updated)
![GitHub last release date](https://img.shields.io/github/release-date/passteque/gluetun?label=Last%20release%20date)
![Commits since release](https://img.shields.io/github/commits-since/passteque/gluetun/latest?sort=semver)

[![Latest size](https://img.shields.io/docker/image-size/qmcgaw/gluetun/latest?label=Latest%20image)](https://hub.docker.com/r/qmcgaw/gluetun/tags)

[![GitHub last commit](https://img.shields.io/github/last-commit/passteque/gluetun.svg)](https://github.com/passteque/gluetun/commits/master)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/y/passteque/gluetun.svg)](https://github.com/passteque/gluetun/graphs/contributors)
[![GitHub closed PRs](https://img.shields.io/github/issues-pr-closed/passteque/gluetun.svg)](https://github.com/passteque/gluetun/pulls?q=is%3Apr+is%3Aclosed)
[![GitHub issues](https://img.shields.io/github/issues/passteque/gluetun.svg)](https://github.com/passteque/gluetun/issues)
[![GitHub closed issues](https://img.shields.io/github/issues-closed/passteque/gluetun.svg)](https://github.com/passteque/gluetun/issues?q=is%3Aissue+is%3Aclosed)

![Code size](https://img.shields.io/github/languages/code-size/passteque/gluetun)
![GitHub repo size](https://img.shields.io/github/repo-size/passteque/gluetun)
![Go version](https://img.shields.io/github/go-mod/go-version/passteque/gluetun)

![Visitors count](https://visitor-badge.laobi.icu/badge?page_id=gluetun.readme)

## Quick links

- [Setup](#setup)
- [Features](#features)
- Problem?
  - Check the Wiki [common errors](https://github.com/qdm12/gluetun-wiki/tree/main/errors) and [faq](https://github.com/qdm12/gluetun-wiki/tree/main/faq)
  - [Start a discussion](https://github.com/passteque/gluetun/discussions)
  - [Fix the Unraid template](https://github.com/passteque/gluetun/discussions/550)
- Suggestion?
  - [Create an issue](https://github.com/passteque/gluetun/issues)
- Happy?
  - Sponsor me on [github.com/sponsors/qdm12](https://github.com/sponsors/qdm12)
  - Donate to [paypal.me/qmcgaw](https://www.paypal.me/qmcgaw)
  - Drop me [an email](mailto:quentin.mcgaw@gmail.com)
- **Want to add a VPN provider?** check [the development page](https://github.com/qdm12/gluetun-wiki/blob/main/contributing/development.md) and [add a provider page](https://github.com/qdm12/gluetun-wiki/blob/main/contributing/add-a-provider.md)
- Video:

  [![Video Gif](https://i.imgur.com/CetWunc.gif)](https://youtu.be/0F6I03LQcI4)

- [Substack Console interview](https://console.substack.com/p/console-72)

## Features

- Based on Alpine 3.23 for a small Docker image of 43.1MB
- Supports: **AirVPN**, **Cyberghost**, **ExpressVPN**, **FastestVPN**, **Giganews**, **HideMyAss**, **IPVanish**, **IVPN**, **Mullvad** (Wireguard only), **NordVPN**, **Ovpn**, **Perfect Privacy**, **Privado**, **Private Internet Access**, **PrivateVPN**, **ProtonVPN**, **PureVPN**,  **SlickVPN**, **Surfshark**, **TorGuard**, **VPNSecure.me**, **VPNUnlimited**, **Vyprvpn**, **Windscribe** servers
- Supports OpenVPN for all providers listed
- Supports Wireguard both kernelspace and userspace
  - For **AirVPN**, **FastestVPN**, **Ivpn**, **Mullvad**, **NordVPN**, **Ovpn**, **Perfect privacy**, **ProtonVPN**, **Surfshark** and **Windscribe**
  - For **Cyberghost**, **Private Internet Access**, **PrivateVPN**, **PureVPN**, **Torguard**, **VPN Unlimited** and **VyprVPN** using [the custom provider](https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/custom.md)
  - For custom Wireguard configurations using [the custom provider](https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/custom.md)
  - More in progress, see [#134](https://github.com/passteque/gluetun/issues/134)
- Supports AmneziaWG only with the custom provider for now
- DNS over TLS baked in with service provider(s) of your choice
- DNS fine blocking of malicious/ads/surveillance hostnames and IP addresses, with live update every 24 hours
- Choose the vpn network protocol, `udp` or `tcp`
- Built in firewall kill switch to allow traffic only with needed the VPN servers and LAN devices
- Built in Shadowsocks proxy server (protocol based on SOCKS5 with an encryption layer, tunnels TCP+UDP)
- Built in Socks5 proxy server (tunnels TCP+UDP) - partial credits to @angelakis and @adjscent
- Built in HTTP proxy (tunnels HTTP and HTTPS through TCP)
- [Connect other containers to it](https://github.com/qdm12/gluetun-wiki/blob/main/setup/connect-a-container-to-gluetun.md)
- [Connect LAN devices to it](https://github.com/qdm12/gluetun-wiki/blob/main/setup/connect-a-lan-device-to-gluetun.md)
- Compatible with amd64, i686 (32 bit), **ARM** 64 bit, ARM 32 bit v6 and v7, and even ppc64le 🎆
- Custom VPN server side port forwarding for [Perfect Privacy](https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/perfect-privacy.md#vpn-server-port-forwarding), [Private Internet Access](https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/private-internet-access.md#vpn-server-port-forwarding), [PrivateVPN](https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/privatevpn.md#vpn-server-port-forwarding) and [ProtonVPN](https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/protonvpn.md#vpn-server-port-forwarding)
- Possibility of split horizon DNS by selecting multiple DNS over TLS providers
- Can work as a Kubernetes sidecar container, thanks @rorph

## Setup

🎉 There are now instructions specific to each VPN provider with examples to help you get started as quickly as possible!

Go to the [Wiki](https://github.com/qdm12/gluetun-wiki)!

[🐛 Found a bug in the Wiki?!](https://github.com/qdm12/gluetun-wiki/issues/new/choose)

Here's a docker-compose.yml for the laziest:

```yml
---
services:
  gluetun:
    image: qmcgaw/gluetun
    # container_name: gluetun
    # line above must be uncommented to allow external containers to connect.
    # See https://github.com/qdm12/gluetun-wiki/blob/main/setup/connect-a-container-to-gluetun.md#external-container-to-gluetun
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    ports:
      - 8888:8888/tcp # HTTP proxy
      - 8388:8388/tcp # Shadowsocks
      - 8388:8388/udp # Shadowsocks
    volumes:
      - /yourpath:/gluetun
    environment:
      # See https://github.com/qdm12/gluetun-wiki/tree/main/setup#setup
      - VPN_SERVICE_PROVIDER=ivpn
      - VPN_TYPE=openvpn
      # OpenVPN:
      - OPENVPN_USER=
      - OPENVPN_PASSWORD=
      # Wireguard:
      # - WIREGUARD_PRIVATE_KEY=wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=
      # - WIREGUARD_ADDRESSES=10.64.222.21/32
      # Timezone for accurate log times
      - TZ=
      # Server list updater
      # See https://github.com/qdm12/gluetun-wiki/blob/main/setup/servers.md#update-the-vpn-servers-list
      - UPDATER_PERIOD=
```

🆕 Image also available as `ghcr.io/qdm12/gluetun`

## Fun graphs

[![Star History Chart](https://api.star-history.com/svg?repos=passteque/gluetun&type=date&legend=top-left)](https://www.star-history.com/#passteque/gluetun&type=date&legend=top-left)

## License

[![MIT](https://img.shields.io/github/license/passteque/gluetun)](https://github.com/passteque/gluetun/blob/master/LICENSE)
