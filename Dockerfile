# Dockerfile
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Instala dependencias: compilación del CLI, jq y netcat para healthchecks
RUN apt-get update && apt-get install -y \
    bash curl ca-certificates git jq pkg-config build-essential libssl-dev netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Instala Rust para compilar deltachat-cli
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Compila e instala deltachat-cli
RUN git clone --depth=1 https://github.com/deltachat/deltachat-core-rust.git /src/dc && \
    cd /src/dc && \
    cargo build --release --bin deltachat-cli && \
    cp target/release/deltachat-cli /usr/local/bin/deltachat-cli && \
    strip /usr/local/bin/deltachat-cli && \
    rm -rf /src/dc

# Directorio para la base de datos de DeltaChat
RUN mkdir -p /data
VOLUME ["/data"]

# Copia scripts
WORKDIR /app
COPY bot.sh start.sh /app/
RUN chmod +x /app/*.sh

# Punto de entrada
CMD ["/app/start.sh"]