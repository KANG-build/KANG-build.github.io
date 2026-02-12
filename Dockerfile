# Node + Ruby(Jekyll) 같이 쓰기 편한 베이스
FROM node:20-bookworm

# Ruby/Jekyll 설치
RUN apt-get update && apt-get install -y \
    ruby-full build-essential zlib1g-dev \
    && gem install jekyll bundler \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Node deps 먼저
COPY package.json package-lock.json* yarn.lock* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

# 나머지 소스
COPY . .

# Render는 PORT 환경변수를 줌
ENV NODE_ENV=production

# 서버 실행 (너 파일명에 맞춰)
CMD ["node", "blog-api.js"]
