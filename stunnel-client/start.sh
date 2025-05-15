#!/bin/sh

docker run --rm -it \
  --network tls-net \
  --hostname stunnel-client \
  --name stunnel-client \
  -p 8443:8443 \
  stunnel-tls10

