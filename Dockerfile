# cpanel-mail-mcp (fork ruralhackers) — HTTP MCP server image, multi-user.
#
# Users live in /data/users.json (mount a volume there): passwords encrypted
# with MCP_USERS_KEY, tokens stored as hashes. Required env: MCP_USERS_KEY.
# Optional: MCP_SIGNUP_CODE + MCP_PUBLIC_URL to enable the /alta signup page.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin mcp \
 && install -d -m 700 -o mcp -g mcp /data

USER mcp
ENV MCP_TRANSPORT=streamable-http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8080 \
    EMAIL_USERS_FILE=/data/users.json
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('MCP_PORT', '8080'), timeout=3)"]

CMD ["cpanel-mail-mcp"]
