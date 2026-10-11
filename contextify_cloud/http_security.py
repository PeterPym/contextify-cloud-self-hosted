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


def _valid_ip(value: str | None) -> str | None:
    """Return the candidate if it is a valid IP address, else None."""
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        ip_address(candidate)
    except ValueError:
        return None
    return candidate


def _rightmost_forwarded_for(value: str | None) -> str | None:
    """Return the genuine rightmost X-Forwarded-For hop, if it is a valid IP.

    The rightmost entry is the hop the trusted proxy appended (the real
    client). The leftmost is client-supplied and spoofable, so it is never
    used here. Crucially, we take ONLY the last non-empty token and validate
    IT: we do not scan further left for the first valid token. If an attacker
    seeds a valid-looking IP to the left and the genuine rightmost hop is
    garbage, this returns None so the caller falls back to the peer IP rather
    than trusting the attacker's value.
    """
    if not value:
        return None
    tokens = [token.strip() for token in value.split(",")]
    non_empty = [token for token in tokens if token]
    if not non_empty:
        return None
    return _valid_ip(non_empty[-1])


def resolve_client_ip(request: Request) -> str:
    """Resolve the real client IP behind the trusted reverse proxy.

    Trust is the shared config-driven check (loopback plus any CIDR in
    settings.trusted_proxy_cidrs). In production nginx reaches the API through
    a published Docker port, so the peer is the bridge gateway, not loopback;
    TRUSTED_PROXY_CIDRS covers it. For untrusted (direct) peers, forwarding
    headers are ignored so a client cannot choose its own IP. For trusted
    peers, the client comes from X-Real-IP, then the rightmost X-Forwarded-For
    hop, falling back to the peer IP. Never raises and never returns "".
    """
    peer_ip = request.client.host if request.client else "unknown"
    if not _is_trusted_proxy_peer(peer_ip):
        return peer_ip
    real_ip = _valid_ip(request.headers.get("x-real-ip"))
    if real_ip is not None:
        return real_ip
    forwarded = _rightmost_forwarded_for(request.headers.get("x-forwarded-for"))
    if forwarded is not None:
        return forwarded
    return peer_ip


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
