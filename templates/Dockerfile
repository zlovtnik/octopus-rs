# Build with --platform linux/amd64 from the ssl-proxy workspace root.
# The umbrella context supplies the canonical Redpanda topic resources.
FROM rust:1.100.0-slim-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential cmake libcurl4-openssl-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY services/octopus-rs/Cargo.toml services/octopus-rs/Cargo.lock services/octopus-rs/rust-toolchain.toml ./
COPY services/octopus-rs/src/ ./src/
COPY services/octopus-rs/resources/ ./resources/
RUN cargo build --locked --release --bin octopus

FROM debian:bookworm-slim
ARG PARENT_COMMIT
ARG OCTOPUS_COMMIT
RUN test -n "$PARENT_COMMIT" && test -n "$OCTOPUS_COMMIT" \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata wget bash libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 coordinator \
    && useradd --uid 1000 --gid 1000 --no-create-home coordinator
LABEL org.opencontainers.image.revision="$PARENT_COMMIT" \
      io.ssl-proxy.octopus.revision="$OCTOPUS_COMMIT"
ENV TZ=America/New_York
WORKDIR /app
COPY --from=builder --chown=1000:1000 /build/target/release/octopus /app/octopus
COPY --from=builder --chown=1000:1000 /build/resources/ /app/resources/
COPY --chown=1000:1000 docker/redpanda/ /app/docker/redpanda/
RUN chown 1000:1000 /app \
    && chmod 500 /app /app/octopus \
    && chmod -R a=rX /app/resources /app/docker/redpanda
EXPOSE 8081
HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=20s \
    CMD wget -qO- http://localhost:8081/health || exit 1
USER 1000:1000
ENTRYPOINT ["/app/octopus"]
