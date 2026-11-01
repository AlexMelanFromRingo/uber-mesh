# Runtime image for the uber-mesh netem cluster harness. Uses the prebuilt release binary
# (glibc 2.39 → ubuntu:24.04 matches). iproute2 provides `tc` for tc-netem impairment.
#
# Pinned by tag AND digest (reproducible, tamper-evident). Bump both together.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged runtime user. The node never needs root; only applying tc-netem does, and the
# entrypoint drops to this user (setpriv) right after that.
ARG UMESH_UID=10001
RUN groupadd --system --gid "${UMESH_UID}" umesh \
    && useradd --system --uid "${UMESH_UID}" --gid umesh --home-dir /data --shell /usr/sbin/nologin umesh \
    && install -d -o umesh -g umesh -m 0700 /data

COPY --chmod=0755 target/release/uber-mesh /usr/local/bin/uber-mesh
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/entrypoint.sh

ENV RUST_LOG=info
# Non-root by default. Bench containers that need tc-netem run with `user: "0:0"` + NET_ADMIN
# (see compose.yml); the entrypoint then drops back to `umesh` before starting the node.
USER umesh
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
