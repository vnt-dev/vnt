ARG RUST_VERSION=1.93.1

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY .cargo ./.cargo
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY vnt-core ./vnt-core
COPY vnt-ipc ./vnt-ipc
COPY vnt-jni ./vnt-jni
COPY vnt-web ./vnt-web

RUN cargo build --release --locked --bin vnt2_web --features vnt-web

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/data

COPY --from=builder /build/target/release/vnt2_web /usr/local/bin/vnt2_web

VOLUME ["/app/data"]

EXPOSE 19099/tcp

CMD ["vnt2_web", "--addr", "0.0.0.0:19099"]
