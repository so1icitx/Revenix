FROM rust:1.83-bookworm AS builder
WORKDIR /app

# Install libpcap development libraries
RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libpcap0.8 libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/revenix-core /usr/local/bin/revenix-core
CMD ["revenix-core"]
