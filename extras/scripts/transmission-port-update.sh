#!/bin/sh

# Description: This script updates the peer port for the Transmission torrent
# client using its RPC API.
# Author: Juan Luis Font

# default values
DEFAULT_URL="http://localhost:9091/transmission/rpc"
WGET_OPTS=""

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Update Transmission peer-port via RPC API"
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help message and exit."
    echo "  -u, --user USER  Specify the Transmission RPC user name."
    echo "                   (Omit if not required)"
    echo "  -p, --pass PASS  Specify the Transmission RPC password."
    echo "                   (Omit if not required)"
    echo "  -P, --port PORT  Specify the Transmission Peer Port."
    echo "                   If PORT is a comma-separated list of ports,"
    echo "                   only use the first one."
    echo "                   REQUIRED"
    echo "  -U, --url  URL   Specify the Transmission RPC URL."
    echo "                   DEFAULT: ${DEFAULT_URL}"
    echo "Example:"
    echo "  $0 -u admin -p **** 40409"
}

while [ $# -gt 0 ]; do
    case "$1" in
    -h | --help)
        usage
        exit 0
        ;;
    -u | --user)
        USERNAME="$2"
        _USECRED=true
        shift 2
        ;;
    -p | --pass)
        PASSWORD="$2"
        _USECRED=true
        shift 2
        ;;
    -P | --port)
        PORTS="$2"
        PORT=$(echo "$PORTS" | cut -d',' -f1)
        shift 2
        ;;
    -U | --url)
        RPC_URL="$2"
        shift 2
        ;;
    *)
        echo "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
done

if [ -z "${PORT}" ]; then
    echo "ERROR: No Transmission peer-port provided!"
    exit 1
fi

if [ "${_USECRED}" ]; then
    # make sure username AND password were provided
    if [ -z "${USERNAME}" ]; then
        echo "ERROR: Transmission RPC Username not provided."
        exit 1
    fi
    if [ -z "${PASSWORD}" ]; then
        echo "ERROR: Transmission RPC Password not provided."
        exit 1
    fi
    # basic auth options, --auth-no-challenge avoids 409 Conflict
    WGET_OPTS="
            --auth-no-challenge
            --user=${USERNAME}
            --password=${PASSWORD}
        "
fi

if [ -z "${RPC_URL+x}" ]; then
    RPC_URL="${DEFAULT_URL}"
fi

# get the X-Transmission-Session-Id
# shellcheck disable=SC2086
SESSION_ID=$(
    wget \
        --quiet \
        ${WGET_OPTS} \
        --server-response \
        "$RPC_URL" 2>&1 |
        grep 'X-Transmission-Session-Id:' |
        awk '{print $2}'
)

# generate payload string
PAYLOAD=$(printf '{
  "method": "session-set",
  "arguments": {
    "peer-port": %s
  }
}' "$PORT")

# update peer host via API
# shellcheck disable=SC2086
RES=$(
    wget \
        --quiet \
        ${WGET_OPTS} \
        --header="Content-Type: application/json" \
        --header="X-Transmission-Session-Id: $SESSION_ID" \
        --post-data="${PAYLOAD}" \
        "$RPC_URL" \
        -O -
)

# check string returned by wget
SUCCESS='{"arguments":{},"result":"success"}'
if [ "$RES" != "$SUCCESS" ]; then
    echo "ERROR: Could not update Transmission peer-port: ${RES}"
    exit 1
fi

echo "Success! Transmission peer-port updated to ${PORT}"
exit 0
