FROM debian:bullseye-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      python3 python3-pip \
      openssl libssl1.1 libssl-dev \
      ca-certificates nano && \
    rm -rf /var/lib/apt/lists/*

RUN sed -i \
    -e 's/MinProtocol = TLSv1.2/MinProtocol = TLSv1/' \
    -e 's/CipherString = DEFAULT@SECLEVEL=2/CipherString = DEFAULT@SECLEVEL=1/' \
    /etc/ssl/openssl.cnf

RUN echo "deb http://deb.debian.org/debian buster main" \
       > /etc/apt/sources.list.d/buster.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      curl=7.64.0-4+deb10u2 libcurl4=7.64.0-4+deb10u2 && \

    rm /etc/apt/sources.list.d/buster.list && \
    rm -rf /var/lib/apt/lists/*

RUN openssl version -a && \
    openssl ciphers -v 'TLSv1' && \
    curl --version

RUN pip3 install --no-cache-dir requests

WORKDIR /app
CMD ["/bin/bash"]
