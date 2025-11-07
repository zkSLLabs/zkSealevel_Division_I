FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/root/.rustup \
    CARGO_HOME=/root/.cargo \
    PATH=/root/.cargo/bin:/root/.local/share/solana/install/active_release/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl build-essential pkg-config libssl-dev clang cmake git python3 \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (stable)
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable

# Install Solana CLI (1.18.26)
RUN sh -c "$(curl -sSfL https://release.solana.com/v1.18.26/install)" && solana --version

# Install Anchor CLI (0.30.1)
RUN cargo install anchor-cli --version 0.30.1 && anchor --version

WORKDIR /work

CMD ["bash"]


