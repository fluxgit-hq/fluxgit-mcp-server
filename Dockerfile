# Build stage
FROM rust:1.87-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

# Runtime: the sidecar shells out to `git`, so the image must include it.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/fluxgit-mcp-sidecar /usr/local/bin/fluxgit-mcp-sidecar
# MCP stdio transport: the host talks JSON-RPC over stdin/stdout.
ENTRYPOINT ["fluxgit-mcp-sidecar"]
