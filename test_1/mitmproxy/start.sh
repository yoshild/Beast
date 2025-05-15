#!/bin/sh

docker run --rm -it \
  --network tls-net \
  --hostname mitmproxy \
  --name mitmproxy \
  -v "$(pwd)/dump_blocks.py:/app/dump_blocks.py" \
  -v /tmp:/tmp \
  mitmproxy:7.0.4 \
  mitmdump -p 8080 -s /app/dump_blocks.py --mode upstream:http://stunnel-client:8443 --set tls_version_server_min=TLS1

