# Runtime image for the uber-mesh netem cluster harness. Uses the prebuilt release binary
# (glibc 2.39 → ubuntu:24.04 matches). iproute2 provides `tc` for tc-netem impairment.
FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY target/release/uber-mesh /usr/local/bin/uber-mesh
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
