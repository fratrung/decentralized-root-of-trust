# One image for the XMSS raw/SNARK and ML-DSA demo roles.
#
# Every node in the demo runs the same image and differs only by environment,
# which is the point: there is no privileged coordinator to build separately.

FROM rust:1-bookworm AS builder

WORKDIR /src
COPY . .

# The demo is its own crate, so this never rebuilds the measured one into
# something the benchmark did not produce. `--release` is not optional: the
# leanVM prover is unusable at `opt-level = 0`.
RUN cargo build --release --locked --jobs 2 --manifest-path demo/Cargo.toml --bins

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/demo/target/release/bootstrap /usr/local/bin/bootstrap
COPY --from=builder /src/demo/target/release/signer    /usr/local/bin/signer
COPY --from=builder /src/demo/target/release/holder    /usr/local/bin/holder
COPY --from=builder /src/demo/target/release/probe     /usr/local/bin/probe
COPY --from=builder /src/demo/target/release/mldsa_bootstrap /usr/local/bin/mldsa-bootstrap
COPY --from=builder /src/demo/target/release/mldsa_signer    /usr/local/bin/mldsa-signer
COPY --from=builder /src/demo/target/release/mldsa_holder    /usr/local/bin/mldsa-holder

# The prover uses a very deep stack. The repository's `.cargo/config.toml` sets
# this for cargo-launched processes; a container runs the binary directly, so it
# has to be set here as well.
ENV RUST_MIN_STACK=536870912

# Line-buffered output, so `docker compose logs -f` shows a round as it happens
# rather than when the pipe fills.
ENV RUST_BACKTRACE=1

CMD ["signer"]
