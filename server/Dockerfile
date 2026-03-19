FROM ubuntu:22.04

RUN apt update && apt install -y \
    g++ \
    libssl-dev \
    libsqlite3-dev

WORKDIR /app
COPY . .

RUN g++ server.cpp -o server -lssl -lcrypto -lsqlite3 -pthread

EXPOSE 8080
CMD ["./server"]
