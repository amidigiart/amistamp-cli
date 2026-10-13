import json
import shutil
import subprocess
from pathlib import Path

import pytest

from amistamp import cli, core, gitmanifest

HERE = Path(__file__).parent


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("AMISTAMP_HOME", str(tmp_path / "home"))


def stamp_file(tmp_path, content=b"hello\n", meaning="Algoritm de calcul neliniar v1.0 — ăîșț", intent="Dovadă de autor înainte de publicare"):
    f = tmp_path / "doc.txt"
    f.write_bytes(content)
    assert cli.main(["file", str(f), "-m", meaning, "-i", intent]) == 0
    return f, Path(str(f) + ".amistamp.json")


def test_roundtrip_and_offline_verify(tmp_path):
    f, proof = stamp_file(tmp_path)
    p = json.loads(proof.read_text(encoding="utf-8"))
    assert p["format"] == "amistamp-proof-2" and p["stamp"]["doc_kind"] == "file"
    assert all(c[1] == "ok" for c in core.verify_proof(p, core.sha256_hex(f.read_bytes())))
    assert cli.main(["verify", str(proof), "--file", str(f), "--offline"]) == 0


def test_tampering_is_detected(tmp_path):
    f, proof = stamp_file(tmp_path)
    p = json.loads(proof.read_text(encoding="utf-8"))
    p["stamp"]["intentie"] = "something else"
    proof.write_text(json.dumps(p, ensure_ascii=False), encoding="utf-8")
    assert cli.main(["verify", str(proof), "--offline"]) == 1
    p2 = json.loads(json.dumps(p))
    f.write_bytes(b"changed\n")
    assert dict((n, s) for n, s, _ in core.verify_proof(p2, core.sha256_hex(f.read_bytes())))["document"] == "fail"


def test_key_is_reused(tmp_path):
    k1, created1 = core.load_or_create_key()
    k2, created2 = core.load_or_create_key()
    assert created1 and not created2
    assert core.public_jwk(k1) == core.public_jwk(k2)


def test_created_at_matches_js_iso_format():
    import re
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", core.iso_now())


def test_requires_meaning_and_intent(tmp_path):
    k, _ = core.load_or_create_key()
    with pytest.raises(ValueError):
        core.make_stamp("00" * 32, "file", "  ", "x", k)


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_site_verifier_accepts_cli_proof(tmp_path):
    """The exact WebCrypto code of amistampai.com must accept a proof made by the CLI (non-ASCII text included)."""
    _, proof = stamp_file(tmp_path, meaning='Sens cu "ghilimele", emoji 🔏 și diacritice', intent="Intenție\nmultilinie")
    out = subprocess.run(["node", str(HERE / "site_verify.mjs"), str(proof)], capture_output=True, text=True, check=True)
    assert json.loads(out.stdout) == {"ok": True, "keyOk": True, "sigOk": True, "hashOk": True}


@pytest.mark.skipif(not shutil.which("git"), reason="git not installed")
def test_git_manifest_stamp_and_verify(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    g = lambda *a: subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True)
    g("init", "-q")
    g("config", "user.email", "t@example.com")
    g("config", "user.name", "t")
    g("config", "core.autocrlf", "false")
    (repo / "a.py").write_bytes(b"print('a')\r\n")
    (repo / "sub").mkdir()
    (repo / "sub" / "b ț.txt").write_bytes(b"\x00\x01binary")
    g("add", "-A")
    g("commit", "-q", "-m", "one")
    commit, manifest = gitmanifest.build_manifest("HEAD", str(repo))
    text = manifest.decode("utf-8")
    assert text.startswith("# amistamp-git-manifest-1\n# commit " + commit)
    assert "sub/b ț.txt" in text and text.count("\n") == 5
    out = tmp_path / "proofs"
    assert cli.main(["git", "HEAD", "-C", str(repo), "-m", "v1", "-i", "release", "-o", str(out)]) == 0
    proof = out / ("amistamp-" + commit[:12] + ".amistamp.json")
    assert cli.main(["verify", str(proof), "--git", "HEAD", "-C", str(repo), "--offline"]) == 0
    # the manifest file next to the proof hashes to doc_hash, so the website can check it as "the document"
    p = json.loads(proof.read_text(encoding="utf-8"))
    assert core.sha256_hex((out / ("amistamp-" + commit[:12] + ".manifest.txt")).read_bytes()) == p["stamp"]["doc_hash"]
    # a new commit changes the manifest
    (repo / "a.py").write_bytes(b"print('b')\n")
    g("commit", "-q", "-am", "two")
    assert cli.main(["verify", str(proof), "--git", "HEAD", "-C", str(repo), "--offline"]) == 1
    assert cli.main(["verify", str(proof), "--git", "HEAD~1", "-C", str(repo), "--offline"]) == 0
