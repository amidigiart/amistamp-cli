"""Deterministic manifest of a git revision: every tracked file with the SHA-256 of its exact bytes.

The stamp's doc_hash is the SHA-256 of this manifest. The manifest file is written next to the proof,
so anyone can check it on amistampai.com (Verify, upload the manifest as the document) or recompute it
from the repository with `amistamp verify --git REV`.
"""
import hashlib
import subprocess

HEADER = "# amistamp-git-manifest-1"


def _git(args, cwd, data=None):
    r = subprocess.run(["git"] + args, cwd=cwd, input=data, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError("git %s: %s" % (" ".join(args), r.stderr.decode("utf-8", "replace").strip()))
    return r.stdout


def build_manifest(rev="HEAD", cwd="."):
    commit = _git(["rev-parse", "--verify", rev + "^{commit}"], cwd).decode().strip()
    tree = _git(["rev-parse", commit + "^{tree}"], cwd).decode().strip()
    entries = []  # (path_bytes, mode, type, object)
    for rec in _git(["ls-tree", "-r", "-z", "--full-tree", commit], cwd).split(b"\0"):
        if not rec:
            continue
        meta, path = rec.split(b"\t", 1)
        mode, typ, obj = meta.decode().split(" ")
        entries.append((path, mode, typ, obj))
    entries.sort(key=lambda e: e[0])
    blobs = [e for e in entries if e[2] == "blob"]
    contents = _read_blobs(cwd, [e[3] for e in blobs])
    lines = [HEADER, "# commit " + commit, "# tree " + tree]
    for path, mode, typ, obj in entries:
        p = path.replace(b"\\", b"\\\\").replace(b"\n", b"\\n").decode("utf-8", "backslashreplace")
        if typ == "blob":
            lines.append("%s %s %s" % (hashlib.sha256(contents[obj]).hexdigest(), mode, p))
        else:  # submodule: only its commit id is known here
            lines.append("%s %s %s" % (typ + ":" + obj, mode, p))
    return commit, ("\n".join(lines) + "\n").encode("utf-8")


def _read_blobs(cwd, objs):
    """Read all blobs in one `git cat-file --batch` call (raw bytes, no line-ending conversion)."""
    if not objs:
        return {}
    uniq = list(dict.fromkeys(objs))
    out = _git(["cat-file", "--batch"], cwd, data=("\n".join(uniq) + "\n").encode())
    res, i = {}, 0
    for obj in uniq:
        nl = out.index(b"\n", i)
        _, _, size = out[i:nl].decode().split(" ")
        start = nl + 1
        res[obj] = out[start:start + int(size)]
        i = start + int(size) + 1
    return res
