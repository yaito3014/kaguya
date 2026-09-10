FROM rust:slim AS builder
# protobuf-compiler: build.rs gRPC codegen. build-essential + pkg-config +
# libssl-dev: link native-tls (reqwest -> the OIDC provider over HTTPS).
RUN apt-get update && apt-get install -y \
        protobuf-compiler build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/kaguya-web /usr/local/bin/kaguya-web
COPY static /app/static
ENV KAGUYA_WEB_STATIC_DIR=/app/static
EXPOSE 8090
ENTRYPOINT ["kaguya-web"]
