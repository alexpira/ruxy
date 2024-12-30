FROM rust:1.83.0-slim AS builder

RUN mkdir /app
ADD Cargo.toml /app/Cargo.toml
ADD src /app/src
WORKDIR /app

RUN cargo build --release

FROM debian:stable-slim

COPY --from=builder /app/target/release/ruxy /ruxy

RUN chmod 0777 /ruxy
RUN useradd -ms /bin/bash ruxer
USER ruxer

ENV BIND="0.0.0.0:8080"
EXPOSE 8080

CMD [ "sh", "-c", "/ruxy $OPTS" ]

