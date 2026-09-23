FROM ghcr.io/qdm12/godevcontainer:v0.22-alpine
RUN apk add wireguard-tools htop openssl tcpdump iptables
RUN apk add nodejs npm && npm install markdownlint-cli2 --global && apk del npm
