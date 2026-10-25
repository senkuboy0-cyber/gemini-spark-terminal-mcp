FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs ca-certificates curl wget git python3 python3-pip nano procps \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json server.js ./
ENV PORT=10000
EXPOSE 10000
CMD ["node", "server.js"]
