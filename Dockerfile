# syntax=docker/dockerfile:1

# The same version as rust-toolchain.toml, so the image already has the
# toolchain; that file stays out of the build context, or rustup would
# download its extra components. CI passes the file's version and checks this default.
ARG RUST_VERSION=1.100.0
FROM rust:${RUST_VERSION}-trixie AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked --bin wg-relay \
    && cp target/release/wg-relay /usr/local/bin/wg-relay

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /usr/local/bin/wg-relay /usr/local/bin/wg-relay
# Mount the config here; it holds the relay's private key, so keep it read-only.
ENV WG_RELAY_CONFIG=/etc/wg-relay/relay.toml
ENV RUST_LOG=info
EXPOSE 51820/udp
# Prometheus metrics, off unless metrics_listen or WG_RELAY_METRICS_LISTEN is
# set (e.g. 0.0.0.0:9586). No authentication: publish it only to the host's
# loopback or a private network.
EXPOSE 9586/tcp
ENTRYPOINT ["/usr/local/bin/wg-relay"]
