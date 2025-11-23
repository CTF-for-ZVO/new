FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libhivex-bin \
    python3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

COPY inject_flag.sh /usr/local/bin/inject_flag.sh
RUN sed -i 's/\r$//' /usr/local/bin/inject_flag.sh && chmod +x /usr/local/bin/inject_flag.sh

ENTRYPOINT ["/bin/bash", "/usr/local/bin/inject_flag.sh"]
