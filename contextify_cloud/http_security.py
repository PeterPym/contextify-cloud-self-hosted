"""Shared HTTP security helpers for browser-facing auth flows."""

from functools import lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from fastapi import Request, Response

from contextify_cloud.config import settings

NO_STORE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def apply_no_store_headers(response: Response) -> None:
    """Apply no-store and low-leakage headers to an explicit response object."""
    for key, value in NO_STORE_HEADERS.items():
        response.headers[key] = value


@lru_cache(maxsize=32)
def _trusted_proxy_networks(raw_value: str) -> tuple[IPv4Network | IPv6Network, ...]:
    networks = []
    for item in raw_value.split(","):
        value = item.strip()
        if not value:
            continue
        try:
            networks.append(ip_network(value, strict=False))
        except ValueError:
            continue
    return tuple(networks)


def _is_trusted_proxy_peer(client_host: str) -> bool:
    if client_host in ("localhost",):
        return True
    try:
        client_ip = ip_address(client_host)
    except ValueError:
        return False
    if client_ip.is_loopback:
        return True
    return any(
        client_ip in network
        for network in _trusted_proxy_networks(settings.trusted_proxy_cidrs)
    )


def is_transport_https(request: Request) -> bool:
    """Return whether the request reached the public edge over HTTPS.

    Trust X-Forwarded-Proto only from loopback or configured proxy peers such as
    host-level Caddy/nginx proxying to the loopback-bound API container.
    """
    if request.url.scheme == "https":
        return True
    client_host = request.client.host if request.client else ""
    if _is_trusted_proxy_peer(client_host):
        forwarded_proto = request.headers.get("x-forwarded-proto", "")
        first_proto = forwarded_proto.split(",", 1)[0].strip().lower()
        return first_proto == "https"
    return False


def is_secure_request(request: Request) -> bool:
    """Return whether cookies should be marked Secure for this request.

    Hosted production sets FORCE_SECURE_COOKIES=true, so cookie security does not
    depend on proxy topology. In dev/CI/self-hosted mode, trust
    X-Forwarded-Proto only from a loopback peer such as local nginx.
    """
    if settings.force_secure_cookies:
        return True
    return is_transport_https(request)
