#!/bin/sh

# Sets the aMule TCP and UDP ports to the port forwarded by the VPN provider,
# through the amuleapi REST API. amuled applies the new ports without restarting.

# default values, and initial values of the variables read before being assigned,
# so that none of them is inherited from the environment
PASSWORD=""
TCP_PORT=""
UDP_PORT=""
API_PORT="4713"
API_PORT_SET=false
API_URL=""
PORTS_SET=false

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Update the aMule TCP and UDP ports via its REST API (amuleapi)."
    echo "This script is designed to work with Gluetun's VPN_PORT_FORWARDING_UP_COMMAND."
    echo ""
    echo "Options:"
    echo "  --help             Show this help message and exit"
    echo "  --pass PASS        Specify the amuleapi admin password"
    echo "                     REQUIRED"
    echo "  --tcp-port PORT    Specify the aMule TCP port"
    echo "  --udp-port PORT    Specify the aMule UDP port (Kad and global search)"
    echo "                     At least one of --tcp-port and --udp-port is REQUIRED; an omitted one is left unchanged"
    echo "                     PORT may be a comma-separated list, such as {{PORTS}}: only its first port is used"
    echo "  --api-port PORT    Specify the amuleapi port on 127.0.0.1. Not compatible with --url"
    echo "                     Default: \"${API_PORT}\""
    echo "  --url URL          Specify the amuleapi base URL, including its BasePath if any. Not compatible with --api-port"
    echo "                     Default: \"http://127.0.0.1:API_PORT\""
    echo ""
    echo "Examples:"
    echo "# Same forwarded port for TCP and UDP:"
    echo "VPN_PORT_FORWARDING_UP_COMMAND=/bin/sh -c \"/scripts/amule-port-update.sh --pass **** --tcp-port {{PORT}} --udp-port {{PORT}} --api-port 4713\""
    echo "# TCP only (UDP port disabled in aMule):"
    echo "VPN_PORT_FORWARDING_UP_COMMAND=/bin/sh -c \"/scripts/amule-port-update.sh --pass **** --tcp-port {{PORT}} --api-port 4713\""
}

# require_value OPTION ARG_COUNT VALUE exits if OPTION has no non-empty value.
require_value() {
    if [ "$2" -lt 2 ] || [ -z "$3" ]; then
        echo "ERROR: $1 requires a non-empty argument" >&2
        usage
        exit 1
    fi
}

# check_port OPTION VALUE exits unless VALUE is an integer between 1 and 65535.
# Leading zeros (invalid in JSON) and more than 5 digits (overflow in test) are refused.
# Limits specific to aMule (such as TCP ports above 65532) are checked by amuled itself.
check_port() {
    case "$2" in
    '' | *[!0-9]* | 0* | ??????*)
        echo "ERROR: $1 must be a number between 1 and 65535" >&2
        exit 1
        ;;
    esac
    if [ "$2" -gt 65535 ]; then
        echo "ERROR: $1 must be a number between 1 and 65535" >&2
        exit 1
    fi
}

# api_request runs a quiet wget against amuleapi:
# - aMule may still be starting, so refused connections and 503 (amuled not ready yet) are retried
# - a 10 s timeout keeps an unresponsive API from blocking Gluetun's port forwarding
# - proxy variables are ignored, so the password is never sent to a proxy
api_request() {
    wget --retry-connrefused --retry-on-http-error=503 --tries=5 --timeout=10 --no-proxy -q "$@"
}

# json_string KEY prints the value of the string field KEY found in the JSON on stdin,
# at most 200 characters, with escapes and control characters removed so it is safe to log.
# Escaped double quotes become single quotes so they do not end the value early.
json_string() {
    sed "s/\\\\\"/'/g" | sed -n "s/.*\"$1\" *: *\"\([^\"]*\)\".*/\1/p" |
        sed 's/\\[nrt]/ /g; s/\\//g; s/ *$//' | tr -d '[:cntrl:]' | cut -c1-200
}

while [ $# -gt 0 ]; do
    case "$1" in
    --help)
        usage
        exit 0
        ;;
    --pass)
        require_value "$1" $# "$2"
        PASSWORD="$2"
        shift 2
        ;;
    --tcp-port)
        require_value "$1" $# "$2"
        TCP_PORT="${2%%,*}"
        check_port "$1" "${TCP_PORT}"
        shift 2
        ;;
    --udp-port)
        require_value "$1" $# "$2"
        UDP_PORT="${2%%,*}"
        check_port "$1" "${UDP_PORT}"
        shift 2
        ;;
    --api-port)
        require_value "$1" $# "$2"
        check_port "$1" "$2"
        API_PORT="$2"
        API_PORT_SET=true
        shift 2
        ;;
    --url)
        require_value "$1" $# "$2"
        API_URL="${2%/}"
        shift 2
        ;;
    *)
        echo "ERROR: unknown option: $1" >&2
        usage
        exit 1
        ;;
    esac
done

if [ -z "${PASSWORD}" ]; then
    echo "ERROR: --pass is required but not provided" >&2
    exit 1
fi
# control characters (tab, newline...) would need JSON escapes that are not worth supporting
case "${PASSWORD}" in
*[[:cntrl:]]*)
    echo "ERROR: --pass must not contain control characters" >&2
    exit 1
    ;;
esac

# the PATCH body and the final message list only the ports that were given
if [ -n "${TCP_PORT}" ] && [ -n "${UDP_PORT}" ]; then
    PORTS_JSON="\"tcp_port\":${TCP_PORT},\"udp_port\":${UDP_PORT}"
    PORTS_TEXT="TCP port ${TCP_PORT} and UDP port ${UDP_PORT}"
elif [ -n "${TCP_PORT}" ]; then
    PORTS_JSON="\"tcp_port\":${TCP_PORT}"
    PORTS_TEXT="TCP port ${TCP_PORT}"
elif [ -n "${UDP_PORT}" ]; then
    PORTS_JSON="\"udp_port\":${UDP_PORT}"
    PORTS_TEXT="UDP port ${UDP_PORT}"
else
    echo "ERROR: at least one of --tcp-port and --udp-port is required" >&2
    exit 1
fi

if [ "${API_PORT_SET}" = "true" ] && [ -n "${API_URL}" ]; then
    echo "ERROR: --api-port and --url cannot be used together" >&2
    exit 1
fi
API_URL="${API_URL:-http://127.0.0.1:${API_PORT}}"

# the password is escaped for JSON: backslashes first, then double quotes
JSON_PASSWORD=$(printf '%s' "${PASSWORD}" | sed 's/\\/\\\\/g; s/"/\\"/g')

# login returns the session token in the body; a wrong password is not retried.
# Only JWT characters are accepted in the token, as it is sent back in a header.
LOGIN_RESPONSE=$(api_request -O - --content-on-error \
    --header "Content-Type: application/json" \
    --post-data "{\"password\":\"${JSON_PASSWORD}\"}" \
    "${API_URL}/api/v1/auth/login?include_token=true")
TOKEN=$(printf '%s' "${LOGIN_RESPONSE}" | sed -n 's/.*"token" *: *"\([A-Za-z0-9._-]*\)".*/\1/p')
if [ -z "${TOKEN}" ]; then
    # the amuleapi error, when wget returns it, tells a lockout or a disabled login from other failures;
    # wget returns no body on 401, which amuleapi answers for a wrong password
    ERROR_MESSAGE=$(printf '%s' "${LOGIN_RESPONSE}" | json_string message)
    echo "ERROR: failed to authenticate with amuleapi at ${API_URL}: ${ERROR_MESSAGE:-check the admin password and that amuleapi is reachable}" >&2
    exit 1
fi

# ports are validated numbers, so they are safe to inline in the JSON body
if RESPONSE=$(api_request -O - --content-on-error \
    --header "Authorization: Bearer ${TOKEN}" \
    --header "Content-Type: application/json" \
    --method PATCH \
    --body-data "{\"connection\":{${PORTS_JSON}}}" \
    "${API_URL}/api/v1/preferences"); then
    PORTS_SET=true
fi

# logout revokes the session token whatever the update outcome; its own failure is ignored
api_request -O /dev/null --header "Authorization: Bearer ${TOKEN}" --method POST \
    "${API_URL}/api/v1/auth/logout"

if [ "${PORTS_SET}" != "true" ]; then
    # only the code and message of the amuleapi error envelope are printed, never the raw body.
    # The code, when present, is appended as " (code)".
    ERROR_CODE=$(printf '%s' "${RESPONSE}" | json_string code)
    ERROR_MESSAGE=$(printf '%s' "${RESPONSE}" | json_string message)
    echo "ERROR: failed to set aMule ports: ${ERROR_MESSAGE:-no valid response from amuleapi}${ERROR_CODE:+ (${ERROR_CODE})}" >&2
    exit 1
fi

echo "aMule updated to use ${PORTS_TEXT}"
