FROM python:3.9-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libffi-dev \
        libssl-dev \
        libxml2-dev \
        libxslt1-dev \
        libjpeg-dev \
        zlib1g-dev \
        libpcap-dev \
        curl \
        iproute2 \
        net-tools \
        tcpdump \
        bash \
        git \
        && rm -rf /var/lib/apt/lists/*

RUN pip install mitmproxy==7.0.4 \
    werkzeug==2.0.3 \
    flask==2.0.3

WORKDIR /app

EXPOSE 8080

CMD ["mitmproxy", "-p", "8080"]

