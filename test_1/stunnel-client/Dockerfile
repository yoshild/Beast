FROM debian:bullseye-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    stunnel4 openssl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY stunnel.conf /etc/stunnel/stunnel.conf

RUN mkdir -p /var/run/stunnel && \
    chmod 777 /var/run/stunnel

CMD ["stunnel", "/etc/stunnel/stunnel.conf"]

