from __future__ import annotations

import ctypes
import ipaddress
import re
import sys
from ctypes import wintypes
from urllib.parse import urlsplit


_WEBHOOK_PATH = re.compile(r"^/api(?:/v\d+)?/webhooks/\d+/[A-Za-z0-9._-]+$")
_ENTROPY = b"PremiumWatch/discord-webhook/v1"
_HOSTING_TOKEN_ENTROPY = b"PremiumWatch/github-token/v1"
_HOSTED_STATE_TOKEN_ENTROPY = b"PremiumWatch/hosted-state-token/v1"


class SecretStorageError(RuntimeError):
    pass


def validate_public_http_url(value: str) -> str:
    url = str(value or "").strip()
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").rstrip(".").lower()
        port = parts.port
    except ValueError as exc:
        raise ValueError("Enter a valid public http or https URL.") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or not host or port not in (None, 80, 443):
        raise ValueError("Use a public http or https URL on the standard web port.")
    if port is not None and port != (443 if scheme == "https" else 80):
        raise ValueError("Use a public http or https URL on the standard web port.")
    if parts.username is not None or parts.password is not None or parts.fragment:
        raise ValueError("URLs cannot include embedded credentials or fragments.")
    if host in {"localhost", "localhost.localdomain", "metadata.google.internal"} or host.endswith(".localhost") or host.endswith(".local"):
        raise ValueError("Use a public website host.")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        address = None
    if address is not None and (not address.is_global or address.is_multicast or address.is_unspecified):
        raise ValueError("Use a public website host.")
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        raise ValueError("URL host is not valid.")
    return url


def validate_webhook_url(value: str) -> str:
    url = str(value or "").strip()
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError as exc:
        raise ValueError("Enter a valid Discord webhook URL.") from exc
    if (
        parts.scheme.lower() != "https"
        or host != "discord.com"
        or port not in (None, 443)
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or not _WEBHOOK_PATH.fullmatch(parts.path)
    ):
        raise ValueError("Use an HTTPS Discord webhook URL copied from your server’s Integrations page.")
    return url


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob(data: bytes) -> tuple[_DataBlob, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data)
    blob = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    return blob, buffer


def _protect_with_entropy(value: str, *, entropy_value: bytes, description: str) -> bytes:
    if sys.platform != "win32":
        raise SecretStorageError("Saving this secret requires Windows DPAPI.")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptProtectData.argtypes = [ctypes.POINTER(_DataBlob), wintypes.LPCWSTR, ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob)]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    source, source_buffer = _blob(value.encode("utf-8"))
    entropy, entropy_buffer = _blob(entropy_value)
    result = _DataBlob()
    ok = crypt32.CryptProtectData(ctypes.byref(source), description, ctypes.byref(entropy), None, None, 0x1, ctypes.byref(result))
    if not ok:
        raise SecretStorageError(f"Windows could not protect the secret (error {ctypes.get_last_error()}).")
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        kernel32.LocalFree(result.pbData)
        del source_buffer, entropy_buffer


def _unprotect_with_entropy(value: bytes, *, entropy_value: bytes) -> str:
    if sys.platform != "win32":
        raise SecretStorageError("Reading this saved secret requires the Windows account that saved it.")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(_DataBlob), ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob)]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    source, source_buffer = _blob(bytes(value))
    entropy, entropy_buffer = _blob(entropy_value)
    result = _DataBlob()
    description = wintypes.LPWSTR()
    ok = crypt32.CryptUnprotectData(ctypes.byref(source), ctypes.byref(description), ctypes.byref(entropy), None, None, 0x1, ctypes.byref(result))
    if not ok:
        raise SecretStorageError(f"Windows could not unlock the saved webhook (error {ctypes.get_last_error()}).")
    try:
        return ctypes.string_at(result.pbData, result.cbData).decode("utf-8")
    finally:
        kernel32.LocalFree(result.pbData)
        if description:
            kernel32.LocalFree(description)
        del source_buffer, entropy_buffer


def protect_secret(value: str) -> bytes:
    """Encrypt a webhook URL for the current Windows user with DPAPI."""
    return _protect_with_entropy(value, entropy_value=_ENTROPY, description="Premium Watch Discord webhook")


def unprotect_secret(value: bytes) -> str:
    """Decrypt a webhook URL created by the current Windows user."""
    return _unprotect_with_entropy(value, entropy_value=_ENTROPY)


def protect_hosting_token(value: str) -> bytes:
    """Encrypt a GitHub token for the current Windows user with separate DPAPI entropy."""
    token = str(value or "")
    if not token or len(token) > 500 or "\r" in token or "\n" in token or "\x00" in token:
        raise SecretStorageError("The GitHub token is invalid.")
    return _protect_with_entropy(token, entropy_value=_HOSTING_TOKEN_ENTROPY, description="Premium Watch hosting token")


def unprotect_hosting_token(value: bytes) -> str:
    """Decrypt a GitHub token saved by this Windows account."""
    return _unprotect_with_entropy(value, entropy_value=_HOSTING_TOKEN_ENTROPY)


def protect_cloud_state_token(value: str) -> bytes:
    """Encrypt the read/write state token separately from the local control token."""
    token = str(value or "")
    if not token or len(token) > 500 or "\r" in token or "\n" in token or "\x00" in token:
        raise SecretStorageError("The cloud state token is invalid.")
    return _protect_with_entropy(
        token, entropy_value=_HOSTED_STATE_TOKEN_ENTROPY,
        description="Premium Watch cloud state token",
    )


def unprotect_cloud_state_token(value: bytes) -> str:
    """Decrypt the cloud state token saved by this Windows account."""
    return _unprotect_with_entropy(value, entropy_value=_HOSTED_STATE_TOKEN_ENTROPY)
