FROM rust:1.80 AS build
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:stable-slim
WORKDIR /app
COPY --from=build /app/target/release/prover /usr/local/bin/prover
ENTRYPOINT ["prover"]


