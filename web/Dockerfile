FROM rust:slim@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS builder
# protobuf-compiler: build.rs gRPC codegen. build-essential + pkg-config +
# libssl-dev: link native-tls (reqwest -> the OIDC provider over HTTPS).
RUN apt-get update && apt-get install -y \
        protobuf-compiler build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update && apt-get install -y ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/kaguya-web /usr/local/bin/kaguya-web
COPY static /app/static
ENV KAGUYA_WEB_STATIC_DIR=/app/static
EXPOSE 8090
ENTRYPOINT ["kaguya-web"]
