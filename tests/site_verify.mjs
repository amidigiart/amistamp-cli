// Verifies a CLI proof with the same logic amistampai.com uses in the browser (WebCrypto).
// Functions copied from amistampai.com/index.html: canonical, payloadOf, keyFingerprint, verifyStamp core.
import { readFileSync } from 'node:fs';
const { subtle } = globalThis.crypto;
const enc = new TextEncoder();
function hex(buf) { return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join(''); }
async function sha256Hex(data) { return hex(await subtle.digest('SHA-256', typeof data === 'string' ? enc.encode(data) : data)); }
function unb64(s) { var r = atob(s), a = new Uint8Array(r.length); for (var i = 0; i < r.length; i++) a[i] = r.charCodeAt(i); return a; }
function canonical(obj) { return JSON.stringify(Object.keys(obj).sort().reduce(function (o, k) { o[k] = obj[k]; return o; }, {})); }
function payloadOf(s) {
  return { v: s.v, doc_hash: s.doc_hash, doc_kind: s.doc_kind, sens: s.sens, intentie: s.intentie, created_at: s.created_at, key_fp: s.key_fp };
}
async function keyFingerprint(pub) { return sha256Hex(canonical({ crv: pub.crv, kty: pub.kty, x: pub.x, y: pub.y })); }
function stampFromProof(p) {
  if (!p || p.format !== 'amistamp-proof-2' || !p.stamp || !p.signature || !p.public_key) return null;
  var st = p.stamp;
  return { id: p.id, v: st.v, doc_hash: st.doc_hash, doc_kind: st.doc_kind, sens: st.sens, intentie: st.intentie,
    created_at: st.created_at, key_fp: st.key_fp, stamp_hash: p.stamp_hash, signature: p.signature.value,
    public_key: p.public_key, anchors: Array.isArray(p.anchors) ? p.anchors : [] };
}

const s = stampFromProof(JSON.parse(readFileSync(process.argv[2], 'utf8')));
if (!s || s.v !== 'amistamp-2') { console.log(JSON.stringify({ ok: false, why: 'format' })); process.exit(0); }
const keyOk = (await keyFingerprint(s.public_key)) === s.key_fp;
const bytes = enc.encode(canonical(payloadOf(s)));
let sigOk = false;
try {
  const pub = await subtle.importKey('jwk', { kty: s.public_key.kty, crv: s.public_key.crv, x: s.public_key.x, y: s.public_key.y },
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  sigOk = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, unb64(s.signature), bytes);
} catch (e) { sigOk = false; }
const hashOk = (await sha256Hex(bytes)) === s.stamp_hash;
console.log(JSON.stringify({ ok: keyOk && sigOk && hashOk, keyOk, sigOk, hashOk }));
