FROM rust:1.99-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock README.md ./
COPY src ./src
RUN cargo build --release --bin command-mcp

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/command-mcp /usr/local/bin/command-mcp
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000
CMD ["command-mcp", "server"]
