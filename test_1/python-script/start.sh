#!/bin/sh

docker run --rm -it \
  --network tls-net \
  --hostname client \
  --name tls10-client \
  -v "$(pwd)":/app \
  -v /tmp:/tmp \
  -w /app \
  tls10-python

