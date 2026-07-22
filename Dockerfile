FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    whois dnsutils && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pyyaml python-whois dnspython

COPY . /app

ENTRYPOINT ["./analyze.sh"]
CMD ["--interactive"]
