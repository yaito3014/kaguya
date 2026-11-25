FROM rust:slim@sha256:3b199fd6db7d709274df56565b8f4003f9e30d7bfcff9d53148c86053b7855e2 AS builder
# protobuf-compiler: build.rs codegen. build-essential: C toolchain for ring
# (jsonwebtoken). pkg-config + libssl-dev: link native-tls (reqwest -> the IdP's JWKS).
RUN apt-get update && apt-get install -y \
        protobuf-compiler build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0
# ca-certificates: trust roots for the HTTPS fetch of the IdP's JWKS. libssl3:
# runtime for native-tls.
RUN apt-get update && apt-get install -y ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/kaguya-auth /usr/local/bin/kaguya-auth
EXPOSE 8080
ENTRYPOINT ["kaguya-auth"]
