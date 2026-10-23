FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim
RUN useradd --create-home --uid 10004 mcp
COPY --from=build /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH MCP_SERVER_HOST=0.0.0.0 MCP_SERVER_PORT=8000
USER mcp
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)" || exit 1
CMD ["opencti-mcp-server", "--transport", "http"]
