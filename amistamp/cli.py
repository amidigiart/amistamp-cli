"""amistamp: stamp what your code means and why you made it, from the terminal.

Proofs use the same format as amistampai.com, so they can be verified there or with `amistamp verify`.
"""
import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, core, gitmanifest, tezos

MARK = {"ok": "✓", "fail": "✗", "na": "-"}


def _out(s=""):
    print(s, flush=True)


def _write_proof(p, path):
    Path(path).write_text(json.dumps(p, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def _summary(p, path):
    s = p["stamp"]
    _out("stamp_hash  " + p["stamp_hash"])
    _out("doc_hash    " + s["doc_hash"] + "  (" + s["doc_kind"] + ")")
    _out("created_at  " + s["created_at"])
    _out("key         " + s["key_fp"][:16])
    _out("proof       " + str(path))
    _out()
    _out("Signed on this machine. To add a public date on Tezos: amistamp anchor " + str(path))


def cmd_key(a):
    k, created = core.load_or_create_key()
    fp = core.key_fingerprint(core.public_jwk(k))
    _out(("created " if created else "") + "key " + str(core.key_dir() / "key.pem"))
    _out("fingerprint " + fp)
    _out("Keep a copy of this file: it is the only way to sign as you. Lost key = new key; old proofs stay valid.")


def cmd_file(a):
    f = Path(a.path)
    k, _ = core.load_or_create_key()
    p = core.make_stamp(core.sha256_hex(f.read_bytes()), "file", a.meaning, a.intent, k)
    out = Path(a.output) if a.output else f.with_name(f.name + ".amistamp.json")
    _write_proof(p, out)
    _summary(p, out)


def cmd_git(a):
    commit, manifest = gitmanifest.build_manifest(a.rev, a.repo)
    k, _ = core.load_or_create_key()
    p = core.make_stamp(core.sha256_hex(manifest), "git-manifest", a.meaning, a.intent, k)
    d = Path(a.output_dir)
    d.mkdir(parents=True, exist_ok=True)
    base = d / ("amistamp-" + commit[:12])
    (base.with_suffix(".manifest.txt")).write_bytes(manifest)
    out = base.with_suffix(".amistamp.json")
    _write_proof(p, out)
    _out("commit      " + commit + "  (" + str(manifest.count(b"\n") - 3) + " files)")
    _out("manifest    " + str(base.with_suffix(".manifest.txt")))
    _summary(p, out)


def cmd_verify(a):
    p = json.loads(Path(a.proof).read_text(encoding="utf-8"))
    doc_hash = None
    if a.file:
        doc_hash = core.sha256_hex(Path(a.file).read_bytes())
    elif a.git:
        _, manifest = gitmanifest.build_manifest(a.git, a.repo)
        doc_hash = core.sha256_hex(manifest)
    checks = core.verify_proof(p, doc_hash)
    if not a.offline and p.get("format") == core.PROOF_FORMAT:
        anchors = [x for x in p.get("anchors") or [] if isinstance(x, dict)]
        if not anchors:
            checks.append(("tezos", "na", "no anchor in the proof (amistamp anchor)"))
        for x in anchors:
            r = tezos.check_anchor(x, p.get("stamp_hash", ""))
            checks.append(("tezos", "na" if r is None else "ok" if r else "fail",
                           tezos.EXPLORER + str(x.get("tx")) + ("" if r is not None else " (not checked)")))
    for name, state, detail in checks:
        _out("%s %-11s %s" % (MARK[state], name, detail))
    if isinstance(p.get("stamp"), dict):
        _out()
        _out("meaning     " + str(p["stamp"].get("sens")))
        _out("intent      " + str(p["stamp"].get("intentie")))
    failed = any(c[1] == "fail" for c in checks)
    _out()
    _out("FAILED" if failed else "VERIFIED (signature and hash)" if all(c[1] == "ok" for c in checks[:3]) else "INCOMPLETE")
    return 1 if failed else 0


def cmd_anchor(a):
    p = json.loads(Path(a.proof).read_text(encoding="utf-8"))
    sh = p["stamp_hash"]
    if any(c[1] == "fail" for c in core.verify_proof(p)):
        _out("This proof does not verify; not anchoring it.")
        return 1
    ops = tezos.find_in_registry(sh)
    if ops:
        first = ops[0]
        if not any(x.get("tx") == first["hash"] for x in p.get("anchors") or []):
            p.setdefault("anchors", []).append(tezos.anchor_record(first))
            _write_proof(p, a.proof)
            _out("Found on Tezos and added to the proof:")
        else:
            _out("Already anchored:")
        _out("  " + first["timestamp"] + "  " + tezos.EXPLORER + first["hash"])
        return 0
    _out("Not on Tezos yet. Call the public registry from your own Tezos account (0 tez + a small fee):")
    _out("  contract    " + tezos.REGISTRY + "  (Tezos mainnet)")
    _out("  entrypoint  default")
    _out("  parameter   0x" + sh + "   (Michelson: bytes)")
    _out()
    _out("With octez-client:")
    _out("  octez-client transfer 0 from <your-account> to " + tezos.REGISTRY + " --entrypoint default --arg 0x" + sh)
    _out()
    _out("Then run again: amistamp anchor " + a.proof)
    return 2


def main(argv=None):
    ap = argparse.ArgumentParser(prog="amistamp", description="Stamp what your code means and why you made it. "
                                 "Files never leave your machine; only a hash can go on Tezos.")
    ap.add_argument("--version", action="version", version="amistamp " + __version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def mi(sp):
        sp.add_argument("-m", "--meaning", required=True, help="what it is / what it means")
        sp.add_argument("-i", "--intent", required=True, help="why you made it")

    sp = sub.add_parser("key", help="show (or create) your local signing key")
    sp.set_defaults(fn=cmd_key)

    sp = sub.add_parser("file", help="stamp one file")
    sp.add_argument("path")
    mi(sp)
    sp.add_argument("-o", "--output", help="proof path (default: <file>.amistamp.json)")
    sp.set_defaults(fn=cmd_file)

    sp = sub.add_parser("git", help="stamp a git revision (all tracked files at that commit)")
    sp.add_argument("rev", nargs="?", default="HEAD")
    mi(sp)
    sp.add_argument("-C", dest="repo", default=".", help="repository path")
    sp.add_argument("-o", "--output-dir", default="amistamp-proofs")
    sp.set_defaults(fn=cmd_git)

    sp = sub.add_parser("verify", help="verify a proof (exit 1 if anything fails)")
    sp.add_argument("proof")
    g = sp.add_mutually_exclusive_group()
    g.add_argument("--file", help="the original file")
    g.add_argument("--git", metavar="REV", help="recompute the manifest of this git revision")
    sp.add_argument("-C", dest="repo", default=".")
    sp.add_argument("--offline", action="store_true", help="skip the Tezos check")
    sp.set_defaults(fn=cmd_verify)

    sp = sub.add_parser("anchor", help="find the stamp on Tezos and record it, or show how to anchor it")
    sp.add_argument("proof")
    sp.set_defaults(fn=cmd_anchor)

    a = ap.parse_args(argv)
    if os.name == "nt":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    try:
        return a.fn(a) or 0
    except (ValueError, RuntimeError, OSError) as e:
        print("amistamp: " + str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
