"""Entry point: `opencti-mcp-server [--transport stdio|http] [--host H] [--port P]`."""

from __future__ import annotations

import argparse
import logging


def main() -> None:
    from opencti_mcp_server.config import get_settings

    settings = get_settings()
    parser = argparse.ArgumentParser(prog="opencti-mcp-server")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    # Defaults come from MCP_SERVER_HOST / MCP_SERVER_PORT; flags override them only when given.
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # httpx logs every request URL at INFO; keep the OpenCTI address out of routine logs.
    logging.getLogger("httpx").setLevel(logging.WARNING)

    if not settings.opencti_token.get_secret_value():
        raise SystemExit("OPENCTI_TOKEN is required")

    if args.transport == "stdio":
        from opencti_mcp_server.server import build_server

        build_server(settings).run("stdio")
        return

    import uvicorn

    from opencti_mcp_server.server import build_http_app

    settings.mcp_server_host = args.host or settings.mcp_server_host
    settings.mcp_server_port = args.port or settings.mcp_server_port
    uvicorn.run(
        build_http_app(settings),
        host=settings.mcp_server_host,
        port=settings.mcp_server_port,
        log_level="info",
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
