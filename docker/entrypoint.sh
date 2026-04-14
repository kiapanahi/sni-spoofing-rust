#!/bin/sh
set -e

FAKE_SNI="${FAKE_SNI:-security.vercel.com}"
PROXY_PORT="${PROXY_PORT:-1080}"
LISTEN_PORT=40443

if [ -z "$VLESS_URI" ]; then
    echo "ERROR: VLESS_URI environment variable is required"
    echo ""
    echo "Usage:"
    echo "  docker run -d --cap-add=NET_RAW --cap-add=NET_ADMIN -p ${PROXY_PORT}:${PROXY_PORT} \\"
    echo "    -e VLESS_URI='vless://uuid@server:443?...' \\"
    echo "    -e FAKE_SNI='${FAKE_SNI}' \\"
    echo "    sni-spoof-proxy"
    exit 1
fi

urldecode() {
    python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.argv[1]))" "$1"
}

STRIPPED="${VLESS_URI#vless://}"
STRIPPED=$(echo "$STRIPPED" | sed 's/#.*//')
UUID=$(echo "$STRIPPED" | cut -d'@' -f1)
AFTER_AT=$(echo "$STRIPPED" | cut -d'@' -f2)
SERVER_HOST=$(echo "$AFTER_AT" | cut -d':' -f1)
PORT_AND_PARAMS=$(echo "$AFTER_AT" | cut -d':' -f2)
SERVER_PORT=$(echo "$PORT_AND_PARAMS" | cut -d'?' -f1)
PARAMS=$(echo "$PORT_AND_PARAMS" | cut -d'?' -f2-)

get_param() {
    echo "$PARAMS" | tr '&' '\n' | grep "^${1}=" | head -1 | cut -d'=' -f2-
}

SECURITY=$(get_param "security")
SNI=$(get_param "sni")
SNI=$(echo "$SNI" | sed 's/\.$//')
FP=$(get_param "fp")
NETWORK=$(get_param "type")
HOST=$(get_param "host")
PATH_ENC=$(get_param "path")
MODE=$(get_param "mode")
PATH_DEC=$(urldecode "$PATH_ENC")

EXTRA_ENC=$(get_param "extra")
DOWNLOAD_SETTINGS=""
if [ -n "$EXTRA_ENC" ]; then
    DOWNLOAD_SETTINGS=$(urldecode "$EXTRA_ENC")
fi

RESOLVE_HOST="$SERVER_HOST"
if echo "$SERVER_HOST" | grep -qE '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|localhost|0\.0\.0\.0)'; then
    RESOLVE_HOST="$HOST"
    if [ -z "$RESOLVE_HOST" ]; then
        RESOLVE_HOST="$SNI"
    fi
    SERVER_PORT="${SERVER_PORT:-443}"
fi

echo "Parsed VLESS config:"
echo "  UUID: ${UUID}"
echo "  Network: ${NETWORK}"
echo "  SNI: ${SNI}"
echo "  Host: ${HOST}"
echo "  Path: ${PATH_DEC}"
echo "  Resolving: ${RESOLVE_HOST}"
echo "  Fake SNI: ${FAKE_SNI}"
echo "  Proxy port: ${PROXY_PORT}"

CONNECT_IP=$(getent hosts "$RESOLVE_HOST" 2>/dev/null | head -1 | awk '{print $1}')
if [ -z "$CONNECT_IP" ]; then
    CONNECT_IP=$(nslookup "$RESOLVE_HOST" 2>/dev/null | awk '/^Address: / { print $2 }' | head -1)
fi
if [ -z "$CONNECT_IP" ]; then
    CONNECT_IP=$(dig +short "$RESOLVE_HOST" 2>/dev/null | head -1)
fi
if [ -z "$CONNECT_IP" ]; then
    echo "ERROR: could not resolve ${RESOLVE_HOST}"
    exit 1
fi
echo "  Resolved IP: ${CONNECT_IP}"

CONNECT_PORT="${SERVER_PORT:-443}"
if echo "$SERVER_HOST" | grep -qE '^(127\.|localhost|0\.0\.0\.0)'; then
    CONNECT_PORT=443
fi

cat > /etc/sni-spoof-rs/config.json << SNIEOF
{
  "listeners": [
    {
      "listen": "0.0.0.0:${LISTEN_PORT}",
      "connect": "${CONNECT_IP}:${CONNECT_PORT}",
      "fake_sni": "${FAKE_SNI}"
    }
  ]
}
SNIEOF

STREAM_SETTINGS=""
if [ "$NETWORK" = "xhttp" ]; then
    STREAM_SETTINGS=$(cat << STREAMEOF
"network": "${NETWORK}",
      "security": "${SECURITY}",
      "tlsSettings": {
        "serverName": "${SNI}",
        "fingerprint": "${FP:-chrome}",
        "allowInsecure": false
      },
      "xhttpSettings": {
        "path": "${PATH_DEC}",
        "host": "${HOST}",
        "mode": "${MODE:-auto}"
      }
STREAMEOF
)
elif [ "$NETWORK" = "ws" ]; then
    STREAM_SETTINGS=$(cat << STREAMEOF
"network": "ws",
      "security": "${SECURITY}",
      "tlsSettings": {
        "serverName": "${SNI}",
        "fingerprint": "${FP:-chrome}",
        "allowInsecure": false
      },
      "wsSettings": {
        "path": "${PATH_DEC}",
        "headers": { "Host": "${HOST}" }
      }
STREAMEOF
)
elif [ "$NETWORK" = "grpc" ]; then
    STREAM_SETTINGS=$(cat << STREAMEOF
"network": "grpc",
      "security": "${SECURITY}",
      "tlsSettings": {
        "serverName": "${SNI}",
        "fingerprint": "${FP:-chrome}",
        "allowInsecure": false
      },
      "grpcSettings": {
        "serviceName": "${PATH_DEC}"
      }
STREAMEOF
)
else
    STREAM_SETTINGS=$(cat << STREAMEOF
"network": "${NETWORK:-tcp}",
      "security": "${SECURITY:-tls}",
      "tlsSettings": {
        "serverName": "${SNI}",
        "fingerprint": "${FP:-chrome}",
        "allowInsecure": false
      }
STREAMEOF
)
fi

OUTBOUND_EXTRA=""
if echo "$DOWNLOAD_SETTINGS" | grep -q "downloadSettings"; then
    DL_SNI=$(echo "$DOWNLOAD_SETTINGS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('downloadSettings',{}).get('tlsSettings',{}).get('serverName',''))" 2>/dev/null || echo "")
    DL_FP=$(echo "$DOWNLOAD_SETTINGS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('downloadSettings',{}).get('tlsSettings',{}).get('fingerprint',''))" 2>/dev/null || echo "")
    DL_PATH=$(echo "$DOWNLOAD_SETTINGS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('downloadSettings',{}).get('xhttpSettings',{}).get('path',''))" 2>/dev/null || echo "")
    DL_HOST=$(echo "$DOWNLOAD_SETTINGS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('downloadSettings',{}).get('xhttpSettings',{}).get('host',''))" 2>/dev/null || echo "")
    DL_MODE=$(echo "$DOWNLOAD_SETTINGS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('downloadSettings',{}).get('xhttpSettings',{}).get('mode',''))" 2>/dev/null || echo "")

    if [ -n "$DL_SNI" ]; then
        OUTBOUND_EXTRA=$(cat << DLEOF
,
    "downloadSettings": {
      "address": "127.0.0.1",
      "port": ${LISTEN_PORT},
      "network": "${NETWORK}",
      "security": "${SECURITY}",
      "tlsSettings": {
        "serverName": "${DL_SNI}",
        "fingerprint": "${DL_FP:-chrome}"
      },
      "xhttpSettings": {
        "path": "${DL_PATH:-$PATH_DEC}",
        "host": "${DL_HOST:-$HOST}",
        "mode": "${DL_MODE:-auto}"
      }
    }
DLEOF
)
    fi
fi

cat > /etc/xray/config.json << XRAYEOF
{
  "inbounds": [
    {
      "port": ${PROXY_PORT},
      "listen": "0.0.0.0",
      "protocol": "http",
      "settings": {}
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "127.0.0.1",
            "port": ${LISTEN_PORT},
            "users": [
              {
                "id": "${UUID}",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        ${STREAM_SETTINGS}
      }${OUTBOUND_EXTRA}
    }
  ]
}
XRAYEOF

echo ""
echo "Starting sni-spoof-rs..."
sni-spoof-rs /etc/sni-spoof-rs/config.json &
sleep 1

echo "Starting xray HTTP proxy on port ${PROXY_PORT}..."
echo ""
echo "============================================"
echo "  Proxy ready on port ${PROXY_PORT}"
echo "  Set HTTP proxy on your devices to:"
echo "    <this-machine-ip>:${PROXY_PORT}"
echo "============================================"
echo ""

exec xray run -config /etc/xray/config.json
