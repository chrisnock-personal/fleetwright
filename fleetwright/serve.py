"""
serve.py
~~~~~~~~
Starts the web app. By default it serves HTTPS on 8443 with the certificate
from tls.py, and plain HTTP on 8080 only to redirect browsers to HTTPS.

    python -m fleetwright.serve

FLEETWRIGHT_TLS=off serves plain HTTP on 8080 instead, for running behind a
TLS-terminating proxy.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlsplit

import uvicorn

from . import config, tls

log = logging.getLogger("fleetwright.serve")


async def redirect_app(scope, receive, send):
    if scope["type"] != "http":
        return
    path = scope.get("path", "/")
    query = scope.get("query_string", b"").decode()
    public = urlsplit(config.PUBLIC_URL)
    # Keep the host name the browser used; take the HTTPS port from the public URL.
    host = dict(scope.get("headers") or []).get(b"host", b"").decode().rsplit(":", 1)[0] or public.hostname
    port = f":{public.port}" if public.port and public.port != 443 else ""
    target = f"https://{host}{port}{path}" + (f"?{query}" if query else "")
    await send({"type": "http.response.start", "status": 308,
                "headers": [(b"location", target.encode()), (b"content-length", b"0")]})
    await send({"type": "http.response.body", "body": b""})


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    common = dict(proxy_headers=True, forwarded_allow_ips="*", log_level="info", ws_max_size=2**24)
    if not config.TLS_ON:
        log.warning("FLEETWRIGHT_TLS=off: serving plain HTTP on 8080. Put a TLS proxy in front.")
        await uvicorn.Server(uvicorn.Config("fleetwright.web:app", host="0.0.0.0", port=8080, **common)).serve()
        return
    tls.ensure()
    info = tls.current()
    log.info("HTTPS certificate: %s, SHA-256 %s%s", ", ".join(info.names), info.sha256,
             " (self-signed)" if info.self_signed else "")
    https = uvicorn.Server(uvicorn.Config(
        "fleetwright.web:app", host="0.0.0.0", port=8443, ssl_certfile=str(tls.cert_path()),
        ssl_keyfile=str(tls.key_path()), **common))
    redirect = uvicorn.Server(uvicorn.Config(redirect_app, host="0.0.0.0", port=8080, log_level="warning"))
    redirect.install_signal_handlers = lambda: None
    side = asyncio.create_task(redirect.serve())
    try:
        await https.serve()
    finally:
        redirect.should_exit = True
        await side


if __name__ == "__main__":
    asyncio.run(main())
