#!/usr/bin/env python3
"""Mint a short-lived HS256 bearer token for the HTTP transport.

The server only validates tokens. This helper is for local testing and as a
reference for whatever identity system mints tokens in production (an
internal gateway, a CI OIDC exchange, ...). It reads the same shared secret
file the server uses.

    python examples/mint_http_token.py \\
        --secret-file ~/.config/mcp-sentinel/http-secret \\
        --issuer https://mcp-gateway.internal \\
        --audience mcp-sentinel-detection-engine/prod-1 \\
        --subject alice --ttl 600
"""

from __future__ import annotations

import argparse
import time
import uuid
from pathlib import Path

import jwt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--secret-file", required=True, type=Path)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--audience", required=True)
    parser.add_argument("--subject", default="local-dev")
    parser.add_argument("--ttl", type=int, default=900, help="seconds (server max: 900)")
    args = parser.parse_args()

    secret = args.secret_file.expanduser().read_bytes().strip()
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": args.issuer,
            "aud": args.audience,
            "sub": args.subject,
            "iat": now,
            "exp": now + args.ttl,
            "jti": str(uuid.uuid4()),
        },
        secret,
        algorithm="HS256",
    )
    print(token)


if __name__ == "__main__":
    main()
