"""2F client for Python 3.9+.

Single module. Needs the `cryptography` package for Ed25519 verification.

    client = TwoF(url, api_key, public_keys={"<kid>": "<hex public key>"})
    result = client.authorize(action, idempotency_key="order-991")
    if result.authorized:
        execute(action)
        client.consume(result.receipt)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = ["TwoF", "TwoFError", "Authorization", "canonical", "action_hash", "binding_hash",
           "verify_receipt", "pinned_approvers"]

MAX_SAFE_INTEGER = 2**53 - 1
CLOCK_SKEW = 60


class TwoFError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def canonical(value: Any) -> str:
    """Canonical JSON: RFC 8785 without floating point numbers."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise TwoFError("invalid", "integer outside the safe range")
        return str(value)
    if isinstance(value, float):
        raise TwoFError("invalid", "floating point numbers are not allowed; send amounts as decimal strings")
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TwoFError("invalid", "object keys must be strings")
        # RFC 8785 orders keys by UTF-16 code units, not by code point.
        keys = sorted(value, key=lambda key: key.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(canonical(key) + ":" + canonical(value[key]) for key in keys) + "}"
    raise TwoFError("invalid", "unsupported value in JSON: " + type(value).__name__)


def _tagged_hash(tag: str, text: str) -> bytes:
    return hashlib.sha256((tag + "\n").encode() + text.encode("utf-8")).digest()


def _unb64(text: Any) -> bytes:
    if not isinstance(text, str):
        raise TwoFError("malformed", "invalid base64url")
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    except Exception:
        raise TwoFError("malformed", "invalid base64url") from None


def _ed25519_verify(public_key_hex: str, message: bytes, signature: bytes) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def action_hash(action: Dict[str, Any]) -> str:
    """SHA-256 hash (hex) that identifies an action."""
    return _tagged_hash("2F-ACTION-v1", canonical(action)).hex()


def binding_hash(binding: Dict[str, Any]) -> bytes:
    """The 32 bytes approvers sign."""
    return _tagged_hash("2F-BINDING-v1", canonical(binding))


def _reject_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def verify_receipt(token: str, public_keys: Dict[str, str], action: Dict[str, Any],
                   now: Optional[int] = None) -> Dict[str, Any]:
    """Verifies a receipt for exactly `action`. Raises TwoFError on any failure.

    `public_keys` maps key id to hex public key, as printed by `twof pubkey`.
    """
    now = int(time.time()) if now is None else now
    if not isinstance(token, str) or token.count(".") != 1:
        raise TwoFError("malformed", "receipt is malformed")
    body, signature_text = token.split(".")
    if not body or not signature_text:
        raise TwoFError("malformed", "receipt is malformed")
    payload_bytes = _unb64(body)
    signature = _unb64(signature_text)
    try:
        payload = json.loads(payload_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except Exception:
        raise TwoFError("malformed", "receipt is malformed") from None
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise TwoFError("malformed", "receipt is malformed")
    key = public_keys.get(payload.get("kid")) if isinstance(payload.get("kid"), str) else None
    if not key:
        raise TwoFError("unknown_key", "receipt was signed by an unknown key")
    if not _ed25519_verify(key, b"2F-RECEIPT-v1\n" + payload_bytes, signature):
        raise TwoFError("bad_signature", "receipt signature is invalid")
    for field in ("expires_at", "issued_at"):
        if type(payload.get(field)) is not int:
            raise TwoFError("malformed", "receipt is malformed")
    if not isinstance(payload.get("action_hash"), str):
        raise TwoFError("malformed", "receipt is malformed")
    if now > payload["expires_at"]:
        raise TwoFError("expired", "receipt has expired")
    if payload["issued_at"] > now + CLOCK_SKEW:
        raise TwoFError("not_yet_valid", "receipt is not valid yet")
    if not hmac.compare_digest(action_hash(action), str(payload.get("action_hash"))):
        raise TwoFError("action_mismatch", "receipt was issued for a different action")
    return payload


def pinned_approvers(payload: Dict[str, Any], pinned: Dict[str, str]) -> List[str]:
    """Approvers whose signature verifies against a key you pinned.

    This holds even if the 2F server itself is compromised.
    """
    digest = binding_hash({
        "v": 1, "project": payload["project"], "challenge": payload["challenge"],
        "action_hash": payload["action_hash"], "expires_at": payload["binding_expires_at"],
    })
    names = []
    for approval in payload.get("approvals", []):
        name = approval.get("approver")
        if approval.get("kind") not in ("ed25519", "cosigner") or name not in pinned:
            continue
        try:
            signature = _unb64(approval.get("sig"))
        except TwoFError:
            continue
        if _ed25519_verify(pinned[name], digest, signature) and name not in names:
            names.append(name)
    return names


@dataclass
class Authorization:
    authorized: bool
    state: str
    receipt: Optional[str]
    payload: Optional[Dict[str, Any]]
    challenge: Dict[str, Any]


class TwoF:
    """Talks to a 2F server. Pin `public_keys` in your configuration; do not
    fetch them from the server at runtime."""

    def __init__(self, url: str, api_key: str, public_keys: Dict[str, str], timeout: float = 40.0):
        if not url or not api_key or not public_keys:
            raise TwoFError("invalid", "url, api_key and public_keys are required")
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.public_keys = public_keys
        self.timeout = timeout

    def _request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = canonical(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(self.url + path, data=data, method=method)
        request.add_header("Authorization", "Bearer " + self.api_key)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            try:
                detail = json.loads(error.read().decode("utf-8")).get("error", {})
            except Exception:
                detail = {}
            raise TwoFError(detail.get("code", "http_%d" % error.code),
                            detail.get("message", "request failed")) from None

    def create_challenge(self, action: Dict[str, Any], idempotency_key: str) -> Dict[str, Any]:
        return self._request("POST", "/v1/challenges", {"action": action, "idempotency_key": idempotency_key})

    def get_challenge(self, challenge_id: str, wait_seconds: int = 0) -> Dict[str, Any]:
        path = "/v1/challenges/" + urllib.parse.quote(challenge_id, safe="")
        return self._request("GET", path + ("?wait=%d" % wait_seconds if wait_seconds else ""))

    def authorize(self, action: Dict[str, Any], idempotency_key: str, timeout_seconds: int = 300,
                  on_pending: Optional[Callable[[Dict[str, Any]], None]] = None) -> Authorization:
        """Asks for authorization and waits for the outcome.

        When `authorized` is true the receipt was verified for exactly `action`.
        `on_pending` is called once with the challenge (it carries `approve_url`).
        """
        challenge = self.create_challenge(action, idempotency_key)
        if challenge["state"] == "pending" and on_pending:
            on_pending(challenge)
        deadline = time.time() + timeout_seconds
        while challenge["state"] == "pending" and time.time() < deadline:
            wait = max(1, min(25, int(deadline - time.time()) + 1))
            challenge = self.get_challenge(challenge["id"], wait)
        if challenge["state"] not in ("allowed", "approved"):
            return Authorization(False, challenge["state"], None, None, challenge)
        payload = verify_receipt(challenge["receipt"], self.public_keys, action)
        return Authorization(True, challenge["state"], challenge["receipt"], payload, challenge)

    def consume(self, receipt: str) -> Dict[str, Any]:
        """Marks a receipt as used. Raises with code "conflict" if it was used before."""
        return self._request("POST", "/v1/receipts/consume", {"receipt": receipt})
