FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
# Base tools + archive tools
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git gnupg python3 python3-pip python3-venv \
      build-essential nano less jq procps \
      zip unzip p7zip-full tar gzip xz-utils \
    && (apt-get install -y --no-install-recommends unrar || true) \
    && rm -rf /var/lib/apt/lists/*
# Node.js 22 (NodeSource)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json server.js ./
COPY assets ./assets
ENV PORT=10000
EXPOSE 10000
CMD ["node", "server.js"]
