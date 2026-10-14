# amistamp

Stamp what your code means and why you made it, from the terminal.

A plain hash proves that some bytes existed. An AmiStamp also carries your **meaning** (what it is) and your **intent** (why you made it). All three are signed together on your machine. Optionally, the stamp's hash goes on Tezos to get a public date.

- **Local-first.** Files never leave your machine. Only the 32-byte stamp hash goes on chain, and only if you anchor.
- **Same format as [amistampai.com](https://amistampai.com).** You can verify any proof on the website, with this tool, or by hand (see below).
- **No account, no server.** The signing key is `~/.amistamp/key.pem`.

## Install

```bash
pip install git+https://github.com/amidigiart/amistamp-cli
```

## Use

```bash
# a release: every tracked file at this commit
amistamp git v1.0.0 -m "Nonlinear solver v1.0" -i "Authorship record before the public release"

# one file
amistamp file design.pdf -m "Architecture of the sync engine" -i "Prior record before sharing with partner X"

# check (exit code 1 if anything fails, so it works in CI)
amistamp verify amistamp-proofs/amistamp-<commit>.amistamp.json --git v1.0.0
amistamp verify design.pdf.amistamp.json --file design.pdf

# public date on Tezos (optional)
amistamp anchor design.pdf.amistamp.json
```

`amistamp git` writes two files to `amistamp-proofs/`:
- **`amistamp-<commit>.manifest.txt`:** each tracked file with the SHA-256 of its exact bytes, plus the commit and tree ids.
- **`amistamp-<commit>.amistamp.json`:** the signed proof. Its `doc_hash` is the SHA-256 of the manifest. On the website, upload the manifest as "the document".

## GitHub Action

Stamp every release automatically. The proof and manifest are attached to the release.

```yaml
# .github/workflows/amistamp.yml
on:
  release:
    types: [published]
permissions:
  contents: write
jobs:
  stamp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: amidigiart/amistamp-cli@v0
        with:
          meaning: ${{ github.event.release.name }}
          intent: Authorship record of this release
          key: ${{ secrets.AMISTAMP_KEY }}
```

The key: put your own signing key in the repository secret `AMISTAMP_KEY`, from your machine:

```bash
gh secret set AMISTAMP_KEY --repo OWNER/REPO < ~/.amistamp/key.pem
```

Without it the action uses a one-time key. The proof is still valid, but it is not tied to you.

Outputs: `proof`, `manifest`, `stamp-hash`. For a public date, upload the proof on amistampai.com → Verify → *Anchor this proof on Tezos*, or use `amistamp anchor`.

## Anchoring

`amistamp anchor` never holds a Tezos key. If the stamp hash is not yet on Tezos, it prints the call to make from your own account to the public registry `KT1DhusJXS7BAwM81XS59eAQ6jxijB82bRbJ` (mainnet, entrypoint `default`, parameter = the stamp hash as bytes; the first anchor wins). Run it again afterwards: it finds the operation on TzKT and records it in the proof.

## What a stamp proves, and what it does not

- **It proves:** the key holder signed this exact content, with this meaning and intent. If anchored, the stamp existed no later than the Tezos block time. Before anchoring, the date inside the stamp is the signer's own clock.
- **It does not prove:** that nobody else had the idea first. It is not a patent or patent prior art, since a private stamp is not a publication. It also cannot detect that someone copied and changed your code. It is a dated record of what you declared.

## Verify by hand

1. `stamp_hash` = SHA-256 of `JSON(stamp)`, with keys sorted, no spaces and UTF-8 kept as is.
2. The signature is ECDSA P-256 / SHA-256 over the same bytes, encoded as base64 of r‖s.
3. `key_fp` = SHA-256 of the canonical JSON `{crv,kty,x,y}` of `public_key`.

## Licence

Code: Apache License 2.0 (see `LICENSE` and `NOTICE`). The proof format description ("Verify by hand" and the `amistamp-proof-2` fields): CC BY 4.0. © 2026 Mihai Roșca / BRIDGRAI.

The AmiStampAI website and its analysis services are separate and not covered by this licence.
