"""AmiStampAI stamp model, byte-compatible with amistampai.com (format amistamp-proof-2).

stamp_hash = SHA-256 of JSON(stamp) with sorted keys and no spaces (same as the site's canonical()).
The signature is ECDSA P-256 / SHA-256 over the same bytes, base64, IEEE P1363 (r||s) encoding.
"""
import base64
import hashlib
import json
import os
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature

VERSION = "amistamp-2"
PROOF_FORMAT = "amistamp-proof-2"
PAYLOAD_KEYS = ("v", "doc_hash", "doc_kind", "sens", "intentie", "created_at", "key_fp")


def canonical(obj):
    # JS: JSON.stringify(obj with sorted top-level keys); UTF-8 kept as is, no spaces
    return json.dumps({k: obj[k] for k in sorted(obj)}, ensure_ascii=False, separators=(",", ":"))


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def norm_text(s):
    # same as the site: NFC, CRLF/CR -> LF, trimmed
    return unicodedata.normalize("NFC", s).replace("\r\n", "\n").replace("\r", "\n").strip()


def b64url(n):
    return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()


def unb64url(s):
    return int.from_bytes(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)), "big")


def iso_now():
    # like JS toISOString(): milliseconds, Z
    t = datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (t.microsecond // 1000)


# ---------------- key ----------------

def key_dir():
    return Path(os.environ.get("AMISTAMP_HOME") or Path.home() / ".amistamp")


def public_jwk(private_key):
    nums = private_key.public_key().public_numbers()
    return {"crv": "P-256", "kty": "EC", "x": b64url(nums.x), "y": b64url(nums.y)}


def key_fingerprint(pub):
    return sha256_hex(canonical({"crv": pub["crv"], "kty": pub["kty"], "x": pub["x"], "y": pub["y"]}))


def load_or_create_key():
    """The signing key lives only on this machine: ~/.amistamp/key.pem (or $AMISTAMP_HOME)."""
    d = key_dir()
    p = d / "key.pem"
    if p.exists():
        return serialization.load_pem_private_key(p.read_bytes(), password=None), False
    d.mkdir(parents=True, exist_ok=True)
    k = ec.generate_private_key(ec.SECP256R1())
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return k, True


# ---------------- stamp ----------------

def payload_of(s):
    return {k: s[k] for k in PAYLOAD_KEYS}


def make_stamp(doc_hash, doc_kind, meaning, intent, private_key, created_at=None):
    meaning, intent = meaning.strip(), intent.strip()
    if not meaning or not intent:
        raise ValueError("both --meaning and --intent are required")
    pub = public_jwk(private_key)
    s = {"v": VERSION, "doc_hash": doc_hash, "doc_kind": doc_kind, "sens": meaning, "intentie": intent,
         "created_at": created_at or iso_now(), "key_fp": key_fingerprint(pub)}
    data = canonical(payload_of(s)).encode("utf-8")
    r, sv = decode_dss_signature(private_key.sign(data, ec.ECDSA(hashes.SHA256())))
    sid = str(uuid.uuid4())
    return {
        "format": PROOF_FORMAT,
        "id": sid,
        "stamp": s,
        "stamp_hash": sha256_hex(data),
        "signature": {"alg": "ECDSA-P256-SHA256", "encoding": "base64-ieee-p1363",
                      "value": base64.b64encode(r.to_bytes(32, "big") + sv.to_bytes(32, "big")).decode()},
        "public_key": pub,
        "anchors": [],
        "how_to_verify": "Open amistampai.com, section Verify, choose this file (and optionally the original document). "
                         "Or run: amistamp verify <this file> --file <document>. "
                         "Manually: stamp_hash = SHA-256 of JSON(stamp) with keys sorted and no spaces; the signature is "
                         "ECDSA P-256/SHA-256 over the same bytes; doc_hash = SHA-256 of the file bytes.",
    }


def verify_proof(p, doc_hash=None):
    """Returns a list of (name, state, detail); state is 'ok', 'fail' or 'na'. Offline checks only."""
    checks = []
    if not isinstance(p, dict) or p.get("format") != PROOF_FORMAT or not isinstance(p.get("stamp"), dict):
        return [("format", "fail", "not an amistamp-proof-2 file")]
    s, pub = p["stamp"], p.get("public_key") or {}
    if s.get("v") != VERSION or any(k not in s for k in PAYLOAD_KEYS):
        return [("format", "fail", "unsupported stamp version")]
    fp = key_fingerprint(pub)
    checks.append(("key", "ok" if fp == s["key_fp"] else "fail", fp[:16]))
    data = canonical(payload_of(s)).encode("utf-8")
    try:
        raw = base64.b64decode(p["signature"]["value"])
        if len(raw) != 64:
            raise ValueError
        sig = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        key = ec.EllipticCurvePublicNumbers(unb64url(pub["x"]), unb64url(pub["y"]), ec.SECP256R1()).public_key()
        key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        checks.append(("signature", "ok", ""))
    except (InvalidSignature, ValueError, KeyError, TypeError):
        checks.append(("signature", "fail", ""))
    sh = sha256_hex(data)
    checks.append(("stamp_hash", "ok" if sh == p.get("stamp_hash") else "fail", sh[:16]))
    if doc_hash is None:
        checks.append(("document", "na", "not provided"))
    else:
        checks.append(("document", "ok" if doc_hash == s["doc_hash"] else "fail", doc_hash[:16]))
    return checks
