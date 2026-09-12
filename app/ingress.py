"""Ingress detection helpers.

Home Assistant documents ``172.30.32.2`` as the only peer that should reach
an app through Supervisor ingress.  The add-on launch path disables Uvicorn's
proxy-header rewriting so ``request.client`` remains the transport peer.
Standalone deployments retain their existing reverse-proxy behavior.
"""
import ipaddress
import os

from fastapi import Request

_SUPERVISOR_TOKEN: str | None = os.environ.get("SUPERVISOR_TOKEN")
SUPERVISOR_INGRESS_IP = ipaddress.ip_address("172.30.32.2")


def is_supervisor_peer(request: Request) -> bool:
    """Return whether the request came from the Supervisor ingress proxy."""
    if not _SUPERVISOR_TOKEN or not request.client:
        return False
    try:
        peer = ipaddress.ip_address(request.client.host)
    except (TypeError, ValueError):
        return False
    if isinstance(peer, ipaddress.IPv6Address) and peer.ipv4_mapped:
        peer = peer.ipv4_mapped
    return peer == SUPERVISOR_INGRESS_IP


def get_ingress_path(request: Request) -> str:
    if not is_supervisor_peer(request):
        return ""
    return request.headers.get("X-Ingress-Path", "")


def is_ingress_request(request: Request) -> bool:
    return bool(get_ingress_path(request))


def client_ip(request: Request) -> str:
    """Get the client IP without trusting forwarded headers from add-on peers.

    Standalone deployments continue to rely on their configured reverse proxy
    to overwrite ``X-Forwarded-For``.  In add-on mode, forwarded metadata is
    accepted only after the Supervisor transport peer has been authenticated.
    """
    forwarded = request.headers.get("X-Forwarded-For", "")
    if is_ingress_request(request) and forwarded:
        return forwarded.split(",", 1)[0].strip()
    if _SUPERVISOR_TOKEN:
        return request.client.host if request.client else "unknown"
    return forwarded.split(",", 1)[0].strip() or (request.client.host if request.client else "unknown")
