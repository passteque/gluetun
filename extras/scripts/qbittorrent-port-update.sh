#!/bin/sh

build_default_url() {
    port="${1:-$WEBUI_PORT}"
    echo "http://127.0.0.1:${port}/api"
}

# default values
VPN_PORT=""
VPN_INTERFACE="tun0"
VPN_ADDRESS=""
WEBUI_PORT="8080"
WEBUI_URL=$(build_default_url "$WEBUI_PORT")

# it might take a few tries for qBittorrent to be available (e.g. slow loading with many torrents)
WGET_OPTS="--retry-connrefused --tries=5"

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Update qBittorrent listening port, network interface, and address via its WebUI API."
    echo "This script is designed to work with Gluetun's VPN_PORT_FORWARDING_UP_COMMAND"
    echo "and VPN_PORT_FORWARDING_DOWN_COMMAND."
    echo ""
    echo "WARNING: If you do not provide --iface and --addr, they will be set to default values on every run"
    echo ""
    echo "Options:"
    echo "  --help             Show this help message and exit"
    echo "  --user USER        Specify the qBittorrent username"
    echo "                     (Omit if authentication is disabled for localhost)"
    echo "  --pass PASS        Specify the qBittorrent password"
    echo "                     (Omit if authentication is disabled for localhost)"
    echo "  --port PORT        Specify the qBittorrent listening port (peer-port)"
    echo "                     REQUIRED"
    echo "  --iface IFACE      Specify the network interface to bind to"
    echo "                     Examples: \"\" (any interface), \"lo\", \"eth0\", \"tun0\", etc."
    echo "                     Default: \"${VPN_INTERFACE}\""
    echo "  --addr ADDR        Specify the network address to bind to"
    echo "                     Examples: \"\" (all addresses), \"0.0.0.0\" (all IPv4), \"::\" (all IPv6), or a specific IP"
    echo "                     Default: \"${VPN_ADDRESS}\""
    echo "  --webui-port PORT  Specify the qBittorrent WebUI Port. Not compatible with --url"
    echo "                     Default: \"${WEBUI_PORT}\""
    echo "  --url URL          Specify the qBittorrent API URL. Not compatible with --webui-port"
    echo "                     Default: \"${WEBUI_URL}\""
    echo ""
    echo "Examples:"
    echo "# With authentication:"
    echo "VPN_PORT_FORWARDING_UP_COMMAND=/bin/sh -c \"/scripts/qbittorrent-port-update.sh --user ADMIN --pass **** --port {{PORT}} --iface {{VPN_INTERFACE}} --webui-port 8080\""
    echo "VPN_PORT_FORWARDING_DOWN_COMMAND=/bin/sh -c \"/scripts/qbittorrent-port-update.sh --user ADMIN --pass **** --port 0 --iface lo --webui-port 8080\""
    echo "# Without authentication (\"Bypass authentication for clients on localhost\" enabled in qBittorrent):"
    echo "VPN_PORT_FORWARDING_UP_COMMAND=/bin/sh -c \"/scripts/qbittorrent-port-update.sh --port {{PORT}} --iface {{VPN_INTERFACE}} --webui-port 8080\""
    echo "VPN_PORT_FORWARDING_DOWN_COMMAND=/bin/sh -c \"/scripts/qbittorrent-port-update.sh --port 0 --iface lo --webui-port 8080\""
}

while [ $# -gt 0 ]; do
    case "$1" in
    --help)
        usage
        exit 0
        ;;
    --user)
        if [ $# -lt 2 ] || [ -z "$2" ]; then
            echo "Error: --user requires a non-empty argument."
            usage
            exit 1
        fi
        USERNAME="$2"
        _USECRED=true
        shift 2
        ;;
    --pass)
        if [ $# -lt 2 ] || [ -z "$2" ]; then
            echo "Error: --pass requires a non-empty argument."
            usage
            exit 1
        fi
        PASSWORD="$2"
        _USECRED=true
        shift 2
        ;;
    --port)
        if [ $# -lt 2 ] || [ -z "$2" ]; then
            echo "Error: --port requires a non-empty argument."
            usage
            exit 1
        fi
        VPN_PORT=$(echo "$2" | cut -d',' -f1)
        case "$VPN_PORT" in
            ''|*[!0-9]*)
                echo "Error: --port must be a numeric value between 0 and 65535."
                usage
                exit 1
                ;;
        esac
        if [ "$VPN_PORT" -lt 0 ] || [ "$VPN_PORT" -gt 65535 ]; then
            echo "Error: --port must be between 0 and 65535."
            usage
            exit 1
        fi
        shift 2
        ;;
    --iface)
        if [ $# -lt 2 ] || [ -z "$2" ]; then
            echo "Error: --iface requires a non-empty argument."
            usage
            exit 1
        fi
        VPN_INTERFACE="$2"
        shift 2
        ;;
    --addr)
        if [ $# -lt 2 ] || [ -z "$2" ]; then
            echo "Error: --addr requires a non-empty argument."
            usage
            exit 1
        fi
        VPN_ADDRESS="$2"
        shift 2
        ;;
    --webui-port)
        if [ $# -lt 2 ] || [ -z "$2" ]; then
            echo "Error: --webui-port requires a non-empty argument."
            usage
            exit 1
        fi
        WEBUI_PORT="$2"
        WEBUI_URL=$(build_default_url "$WEBUI_PORT")
        shift 2
        ;;
    --url)
        if [ $# -lt 2 ] || [ -z "$2" ]; then
            echo "Error: --url requires a non-empty argument."
            usage
            exit 1
        fi
        WEBUI_URL="$2"
        shift 2
        ;;
    *)
        echo "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
done

if [ -z "${VPN_PORT}" ]; then
    echo "ERROR: --port is required but not provided"
    exit 1
fi

if [ "${_USECRED}" = "true" ]; then
    # make sure username AND password were provided
    if [ -z "${USERNAME}" ]; then
        echo "ERROR: qBittorrent username not provided"
        exit 1
    fi
    if [ -z "${PASSWORD}" ]; then
        echo "ERROR: qBittorrent password not provided"
        exit 1
    fi

    COOKIE_JAR=$(mktemp)
    if [ ! -w "${COOKIE_JAR}" ]; then
        echo "ERROR: Failed to create temporary cookie jar"
        exit 1
    fi

    wget ${WGET_OPTS} --save-cookies "${COOKIE_JAR}" --keep-session-cookies \
        --header "Referer: ${WEBUI_URL}" \
        --post-data "username=${USERNAME}&password=${PASSWORD}" \
        "${WEBUI_URL}/v2/auth/login" -qO- >/dev/null 2>&1

    if [ $? -ne 0 ] || [ ! -s "${COOKIE_JAR}" ]; then
        echo "ERROR: Failed to authenticate with qBittorrent. Check username/password or verify WebUI is accessible"
        rm -f "${COOKIE_JAR}"
        exit 1
    fi
fi

# update qBittorrent preferences via API, the first call disabled everything and sets safe defaults
# This is required as per https://github.com/qdm12/gluetun-wiki/pull/147 and https://github.com/qdm12/gluetun/issues/2997#issuecomment-3566749335
if [ "${_USECRED}" = "true" ]; then
    wget ${WGET_OPTS} --load-cookies "${COOKIE_JAR}" -qO- --post-data="json={\"random_port\":false,\"upnp\":false,\"listen_port\":0,\"current_network_interface\":\"lo\",\"current_interface_address\":\"127.0.0.1\"}" "$WEBUI_URL/v2/app/setPreferences"
else
    wget ${WGET_OPTS} -qO- --post-data="json={\"random_port\":false,\"upnp\":false,\"listen_port\":0,\"current_network_interface\":\"lo\",\"current_interface_address\":\"127.0.0.1\"}" "$WEBUI_URL/v2/app/setPreferences"
fi
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to reset qBittorrent settings"
    [ "${_USECRED}" = "true" ] && rm -f "${COOKIE_JAR}"
    exit 1
fi

# second call to set the actual port, interface and address
if [ "${_USECRED}" = "true" ]; then
    wget ${WGET_OPTS} --load-cookies "${COOKIE_JAR}" -qO- --post-data="json={\"listen_port\":$VPN_PORT,\"current_network_interface\":\"$VPN_INTERFACE\",\"current_interface_address\":\"$VPN_ADDRESS\"}" "$WEBUI_URL/v2/app/setPreferences"
else
    wget ${WGET_OPTS} -qO- --post-data="json={\"listen_port\":$VPN_PORT,\"current_network_interface\":\"$VPN_INTERFACE\",\"current_interface_address\":\"$VPN_ADDRESS\"}" "$WEBUI_URL/v2/app/setPreferences"
fi
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to apply qBittorrent port/interface settings"
    [ "${_USECRED}" = "true" ] && rm -f "${COOKIE_JAR}"
    exit 1
fi

[ "${_USECRED}" = "true" ] && rm -f "${COOKIE_JAR}"
echo "qBittorrent updated to use peer-port: ${VPN_PORT}, interface: \"${VPN_INTERFACE}\", address: \"${VPN_ADDRESS}\""
