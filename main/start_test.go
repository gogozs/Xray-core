package main

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"github.com/xtls/xray-core/core"
	"testing"
)

func TestConfig(t *testing.T) {
	testData := `{
  "log": {
    "loglevel": "debug"
  },
  "inbounds": [
    {
      "port": 9991,
      "listen": "127.0.0.1",
      "protocol": "http"
    },
    {
      "port": 9992,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {
        "udp": true
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "de.happyplus.lol",
            "port": 443,
            "users": [
              {
                "id": "563b4e74-2f28-4e24-9735-f8b657f04ea9",
                "flow": "xtls-rprx-vision",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": true,
          "fingerprint": "chrome",
          "serverName": "de.happyplus.lol",
          "publicKey": "SeqqT9Gr40YxoAuVNogxoKCh2GmTsO3H25ah7XcaRWg",
          "shortId": "6663456789defabc",
          "spiderX": "/"
        }
      }
    },
    {
      "tag": "direct-out",
      "protocol": "freedom"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "domainMatcher": "hybrid",
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "direct-out"
      },
      {
        "type": "field",
        "ip": [
          "geoip:cn"
        ],
        "outboundTag": "direct-out"
      },
      {
        "domainMatcher": "hybrid",
        "type": "field",
        "domain": ["geosite:cn"],
        "outboundTag": "direct-out"
      }
    ],
    "balancers": []
  }
}
`
	var config core.Config
	err := json.Unmarshal([]byte(testData), &config)
	fmt.Println(config)
	require.Nil(t, err)
}
