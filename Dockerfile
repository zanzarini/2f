FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p twof-cli

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /data twof \
    && mkdir /data && chown twof /data
COPY --from=build /src/target/release/twof /usr/local/bin/twof
USER twof
VOLUME /data
# Set TWOF_KEY (hex seed) as a secret to keep the signing key out of the
# volume that holds the database. Without it a key file is created in /data.
ENV TWOF_DB=/data/twof.db \
    TWOF_KEY_FILE=/data/twof.key \
    TWOF_LISTEN=0.0.0.0:8722 \
    TWOF_AUTO_INIT=true \
    TWOF_TRUST_PROXY=true
EXPOSE 8722
ENTRYPOINT ["twof"]
CMD ["serve"]
