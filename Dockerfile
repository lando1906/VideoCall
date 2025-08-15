FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y curl unzip libcurl4 screen && \
    useradd -m bedrock

WORKDIR /home/bedrock

# Descarga el servidor Bedrock oficial 1.20.40.02
RUN curl -o bedrock.zip https://minecraft.azureedge.net/bin-linux/bedrock-server-1.20.40.02.zip && \
    unzip bedrock.zip && \
    chmod +x bedrock_server && \
    rm bedrock.zip

EXPOSE 19132/tcp

CMD ["./bedrock_server"]