# Gluetun VPN client

⚠️ This and [gluetun-wiki](https://github.com/qdm12/gluetun-wiki) are the only websites for Gluetun, other websites claiming to be official are scams ⚠️

💁 You can optionally set `BORINGPOLL_GLUETUNCOM=on` to... [poll](./internal/boringpoll/boringpoll.go) that **scammy AI slop** website every few minutes so it costs them too much to keep it up. My gentle email reminders to take it down are being grossly ignored 🤷 This would make me very happy and serve this community.

Lightweight swiss-army-knife-like VPN client to multiple VPN service providers

![Title image](https://raw.githubusercontent.com/qdm12/gluetun/master/title.svg)

[![Build status](https://github.com/qdm12/gluetun/actions/workflows/ci.yml/badge.svg)](https://github.com/qdm12/gluetun/actions/workflows/ci.yml)

[![Docker pulls qmcgaw/gluetun](https://img.shields.io/docker/pulls/qmcgaw/gluetun.svg)](https://hub.docker.com/r/qmcgaw/gluetun)
[![Docker pulls qmcgaw/private-internet-access](https://img.shields.io/docker/pulls/qmcgaw/private-internet-access.svg)](https://hub.docker.com/r/qmcgaw/gluetun)

[![Docker stars qmcgaw/gluetun](https://img.shields.io/docker/stars/qmcgaw/gluetun.svg)](https://hub.docker.com/r/qmcgaw/gluetun)
[![Docker stars qmcgaw/private-internet-access](https://img.shields.io/docker/stars/qmcgaw/private-internet-access.svg)](https://hub.docker.com/r/qmcgaw/gluetun)

![Last release](https://img.shields.io/github/release/qdm12/gluetun?label=Last%20release)
![Last Docker tag](https://img.shields.io/docker/v/qmcgaw/gluetun?sort=semver&label=Last%20Docker%20tag)
[![Last release size](https://img.shields.io/docker/image-size/qmcgaw/gluetun?sort=semver&label=Last%20released%20image)](https://hub.docker.com/r/qmcgaw/gluetun/tags?page=1&ordering=last_updated)
![GitHub last release date](https://img.shields.io/github/release-date/qdm12/gluetun?label=Last%20release%20date)
![Commits since release](https://img.shields.io/github/commits-since/qdm12/gluetun/latest?sort=semver)

[![Latest size](https://img.shields.io/docker/image-size/qmcgaw/gluetun/latest?label=Latest%20image)](https://hub.docker.com/r/qmcgaw/gluetun/tags)

[![GitHub last commit](https://img.shields.io/github/last-commit/qdm12/gluetun.svg)](https://github.com/qdm12/gluetun/commits/master)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/y/qdm12/gluetun.svg)](https://github.com/qdm12/gluetun/graphs/contributors)
[![GitHub closed PRs](https://img.shields.io/github/issues-pr-closed/qdm12/gluetun.svg)](https://github.com/qdm12/gluetun/pulls?q=is%3Apr+is%3Aclosed)
[![GitHub issues](https://img.shields.io/github/issues/qdm12/gluetun.svg)](https://github.com/qdm12/gluetun/issues)
[![GitHub closed issues](https://img.shields.io/github/issues-closed/qdm12/gluetun.svg)](https://github.com/qdm12/gluetun/issues?q=is%3Aissue+is%3Aclosed)

![Code size](https://img.shields.io/github/languages/code-size/qdm12/gluetun)
![GitHub repo size](https://img.shields.io/github/repo-size/qdm12/gluetun)
![Go version](https://img.shields.io/github/go-mod/go-version/qdm12/gluetun)

![Visitors count](https://visitor-badge.laobi.icu/badge?page_id=gluetun.readme)

## Quick links

- [Setup](#setup)
- [Features](#features)
- Problem?
  - Check the Wiki [common errors](https://github.com/qdm12/gluetun-wiki/tree/main/errors) and [faq](https://github.com/qdm12/gluetun-wiki/tree/main/faq)
  - [Start a discussion](https://github.com/qdm12/gluetun/discussions)
  - [Fix the Unraid template](https://github.com/qdm12/gluetun/discussions/550)
- Suggestion?
  - [Create an issue](https://github.com/qdm12/gluetun/issues)
- Happy?
  - Sponsor me on [github.com/sponsors/qdm12](https://github.com/sponsors/qdm12)
  - Donate to [paypal.me/qmcgaw](https://www.paypal.me/qmcgaw)
  - Drop me [an email](mailto:quentin.mcgaw@gmail.com)
- **Want to add a VPN provider?** check [the development page](https://github.com/qdm12/gluetun-wiki/blob/main/contributing/development.md) and [add a provider page](https://github.com/qdm12/gluetun-wiki/blob/main/contributing/add-a-provider.md)
- Video:

  [![Video Gif](https://i.imgur.com/CetWunc.gif)](https://youtu.be/0F6I03LQcI4)

- [Substack Console interview](https://console.substack.com/p/console-72)

## Features

- Based on Alpine 3.22 for a small Docker image of 41.1MB
- Supports: **AirVPN**, **Cyberghost**, **ExpressVPN**, **FastestVPN**, **Giganews**, **HideMyAss**, **IPVanish**, **IVPN**, **Mullvad** (Wireguard only), **NordVPN**, **Perfect Privacy**, **Privado**, **Private Internet Access**, **PrivateVPN**, **ProtonVPN**, **PureVPN**,  **SlickVPN**, **Surfshark**, **TorGuard**, **VPNSecure.me**, **VPNUnlimited**, **Vyprvpn**, **Windscribe** servers
- Supports OpenVPN for all providers listed
- Supports Wireguard both kernelspace and userspace
  - For **AirVPN**, **FastestVPN**, **Ivpn**, **Mullvad**, **NordVPN**, **Perfect privacy**, **ProtonVPN**, **Surfshark** and **Windscribe**
  - For **Cyberghost**, **Private Internet Access**, **PrivateVPN**, **PureVPN**, **Torguard**, **VPN Unlimited** and **VyprVPN** using [the custom provider](https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/custom.md)
  - For custom Wireguard configurations using [the custom provider](https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/custom.md)
  - More in progress, see [#134](https://github.com/qdm12/gluetun/issues/134)
- DNS over TLS baked in with service provider(s) of your choice
- DNS fine blocking of malicious/ads/surveillance hostnames and IP addresses, with live update every 24 hours
- Choose the vpn network protocol, `udp` or `tcp`
- Built in firewall kill switch to allow traffic only with needed the VPN servers and LAN devices
- Built in Shadowsocks proxy server (protocol based on SOCKS5 with an encryption layer, tunnels TCP+UDP)
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

[![Star History Chart](https://api.star-history.com/svg?repos=qdm12/gluetun&type=date&legend=top-left)](https://www.star-history.com/#qdm12/gluetun&type=date&legend=top-left)

## License

[![MIT](https://img.shields.io/github/license/qdm12/gluetun)](https://github.com/qdm12/gluetun/blob/master/LICENSE)
