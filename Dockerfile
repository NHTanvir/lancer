# syntax=docker/dockerfile:1.6

# ---- builder ----
FROM rust:1.83-slim AS builder
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN cargo build --release --bin lancer --bin lancer-api

# ---- runtime ----
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/lancer /usr/local/bin/lancer
COPY --from=builder /src/target/release/lancer-api /usr/local/bin/lancer-api

# Persistent volumes
VOLUME ["/data"]
ENV LANCER_LOG=info \
    LANCER_API_TOKEN= \
    RUST_BACKTRACE=1

EXPOSE 8080 9191
WORKDIR /data
ENTRYPOINT ["lancer-api", "--listen", "0.0.0.0:9191", "--project", "/data/lancer.db"]
