FROM ghcr.io/qdm12/godevcontainer:v0.21-alpine
RUN apk add wireguard-tools htop openssl tcpdump iptables
RUN apk add nodejs npm && npm install markdownlint-cli2 --global && apk del npm
