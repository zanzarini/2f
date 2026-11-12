"""Checks this SDK against the random corpus written by the Rust core.
Run through scripts/crosscheck.sh."""
import base64
import hashlib
import json
import pathlib
import sys

from twof import action_hash, binding_hash, canonical

corpus = json.loads((pathlib.Path(__file__).parent.parent / "corpus.json").read_text(encoding="utf-8"))
checked = 0


def fail(what, got, want, source):
    print(f"MISMATCH {what}\n  got:  {got!r}\n  want: {want!r}\n  from: {json.dumps(source)[:300]}")
    sys.exit(1)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


for entry in corpus["values"]:
    got = canonical(entry["value"])
    if got != entry["canonical"]:
        fail("canonical(value)", got, entry["canonical"], entry["value"])
    checked += 1
for entry in corpus["actions"]:
    text = canonical(entry["action"])
    if text != entry["canonical"]:
        fail("canonical(action)", text, entry["canonical"], entry["action"])
    if action_hash(entry["action"]) != entry["hash"]:
        fail("action_hash", action_hash(entry["action"]), entry["hash"], entry["action"])
    if b64(binding_hash(entry["binding"])) != entry["binding_hash"]:
        fail("binding_hash", b64(binding_hash(entry["binding"])), entry["binding_hash"], entry["binding"])
    reject = b64(hashlib.sha256(b"2F-REJECT-v1\n" + canonical(entry["binding"]).encode("utf-8")).digest())
    if reject != entry["reject_hash"]:
        fail("reject hash", reject, entry["reject_hash"], entry["binding"])
    checked += 1
print(f"python agrees with rust on {checked} random cases")
