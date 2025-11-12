FROM rust:alpine AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM alpine:latest
COPY --from=builder /app/target/release/revenix-core /usr/local/bin/revenix-core
CMD ["revenix-core"]
