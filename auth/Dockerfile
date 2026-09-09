FROM rust:slim AS builder
# protobuf-compiler: build.rs codegen. build-essential: C toolchain for ring
# (jsonwebtoken). pkg-config + libssl-dev: link native-tls (reqwest -> Dex JWKS).
RUN apt-get update && apt-get install -y \
        protobuf-compiler build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:trixie-slim
# ca-certificates: trust roots for the HTTPS fetch of Dex's JWKS. libssl3:
# runtime for native-tls.
RUN apt-get update && apt-get install -y ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/kaguya-auth /usr/local/bin/kaguya-auth
EXPOSE 8080
ENTRYPOINT ["kaguya-auth"]
