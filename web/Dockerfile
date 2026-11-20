FROM rust:slim@sha256:6f14b2b4b278ec0d50aa1d69541c304ce0f95e0f6268487aa9924af1c2e9aebe AS builder
# protobuf-compiler: build.rs gRPC codegen. build-essential + pkg-config +
# libssl-dev: link native-tls (reqwest -> the OIDC provider over HTTPS).
RUN apt-get update && apt-get install -y \
        protobuf-compiler build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && apt-get install -y ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/kaguya-web /usr/local/bin/kaguya-web
COPY static /app/static
ENV KAGUYA_WEB_STATIC_DIR=/app/static
EXPOSE 8090
ENTRYPOINT ["kaguya-web"]
