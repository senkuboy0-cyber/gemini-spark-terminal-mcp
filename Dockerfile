FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
# Base tools + archive tools + latest git (git-core PPA)
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget gnupg software-properties-common \
      build-essential nano less jq procps \
      zip unzip p7zip-full tar gzip xz-utils \
    && add-apt-repository -y ppa:git-core/ppa \
    && apt-get update && apt-get install -y --no-install-recommends git \
    && (apt-get install -y --no-install-recommends unrar || true) \
    && rm -rf /var/lib/apt/lists/*
# Node.js 26 (latest line, LTS from Oct 28 2026) + latest npm
RUN ARCH=$(dpkg --print-architecture | sed 's/amd64/x64/') \
    && VER=$(curl -fsSL https://nodejs.org/dist/index.json | jq -r '[.[] | select(.version | startswith("v26."))][0].version') \
    && curl -fsSL "https://nodejs.org/dist/$VER/node-$VER-linux-$ARCH.tar.xz" | tar -xJ -C /usr/local --strip-components=1 \
    && npm install -g npm@latest \
    && rm -rf /root/.npm
# Python 3.15 (latest stable) via uv, made the default python/python3/pip
ENV UV_PYTHON_INSTALL_DIR=/opt/python
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh \
    && uv python install 3.15 \
    && PY=$(uv python find 3.15) \
    && ln -sf "$PY" /usr/local/bin/python3 && ln -sf "$PY" /usr/local/bin/python \
    && ln -sf "$PY" /usr/local/bin/python3.15 \
    && python3 -m ensurepip --upgrade || true
RUN python3 -m pip install --break-system-packages --no-cache-dir --upgrade pip \
    && printf '#!/bin/sh\nexec python3 -m pip "$@"\n' > /usr/local/bin/pip && chmod +x /usr/local/bin/pip \
    && cp /usr/local/bin/pip /usr/local/bin/pip3 \
    && python3 -m pip install --break-system-packages --no-cache-dir cloudscraper requests \
    && python3 --version && pip --version && node -v && npm -v && git --version \
    && python3 -c "import cloudscraper; print('cloudscraper', cloudscraper.__version__)"
WORKDIR /app
COPY package.json server.js ./
COPY assets ./assets
ENV PORT=10000
EXPOSE 10000
CMD ["node", "server.js"]
