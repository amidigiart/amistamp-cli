"""Read-only Tezos checks through the public TzKT API. The CLI never holds a Tezos key:
you anchor from your own wallet (Temple, Kukai) and the CLI finds and records the operation."""
import json
import urllib.parse
import urllib.request

REGISTRY = "KT1DhusJXS7BAwM81XS59eAQ6jxijB82bRbJ"  # public AmiStamp registry, Tezos mainnet; first anchor wins
TZKT = "https://api.tzkt.io"
EXPLORER = "https://tzkt.io/"


def _get(path):
    req = urllib.request.Request(TZKT + path, headers={"User-Agent": "amistamp-cli"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode("utf-8"))


def find_in_registry(stamp_hash):
    """Applied registry calls whose parameter is exactly this stamp hash, oldest first."""
    q = urllib.parse.urlencode({"target": REGISTRY, "parameter": json.dumps(stamp_hash), "status": "applied",
                                "sort.asc": "id", "select": "hash,timestamp,sender"})
    return _get("/v1/operations/transactions?" + q)


def check_anchor(anchor, stamp_hash):
    """True / False, or None when the network or the API cannot be reached."""
    if anchor.get("network") != "mainnet" or not isinstance(anchor.get("tx"), str):
        return None
    try:
        ops = _get("/v1/operations/" + urllib.parse.quote(anchor["tx"]))
    except Exception:
        return None
    return any(o.get("status") == "applied" and stamp_hash in json.dumps(o.get("parameter") or {}).lower() for o in ops)


def anchor_record(op):
    return {"network": "mainnet", "tx": op["hash"], "contract": REGISTRY, "method": "registry", "at": op["timestamp"]}
