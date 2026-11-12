import base64
import json
import pathlib
import unittest

import twof
from twof import TwoFError, action_hash, binding_hash, canonical, pinned_approvers, verify_receipt

VECTORS = json.loads((pathlib.Path(__file__).parent.parent / "vectors.json").read_text(encoding="utf-8"))
R = VECTORS["receipt"]
KEYS = {R["server_kid"]: R["server_public_key"]}


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Vectors(unittest.TestCase):
    def assert_code(self, code, fn, *args):
        with self.assertRaises(TwoFError) as raised:
            fn(*args)
        self.assertEqual(raised.exception.code, code)

    def test_canonical_matches_rust(self):
        for case in VECTORS["canonical"]:
            self.assertEqual(canonical(json.loads(case["input"])), case["output"])

    def test_floats_and_unsafe_integers_are_rejected(self):
        self.assert_code("invalid", canonical, {"a": 1.5})
        self.assert_code("invalid", canonical, {"a": 2**53})
        self.assert_code("invalid", canonical, {1: "a"})

    def test_hashes_match_rust(self):
        for case in VECTORS["actions"]:
            self.assertEqual(canonical(case["action"]), case["canonical"])
            self.assertEqual(action_hash(case["action"]), case["hash"])
        self.assertEqual(b64(binding_hash(VECTORS["binding"]["binding"])), VECTORS["binding"]["hash"])

    def test_receipt_verifies_for_its_action_only(self):
        payload = verify_receipt(R["token"], KEYS, R["action"], R["valid_at"])
        self.assertEqual(payload["challenge"], "ch_test")
        self.assert_code("action_mismatch", verify_receipt, R["token"], KEYS, R["other_action"], R["valid_at"])
        tampered = dict(R["action"], amount="1500.26")
        self.assert_code("action_mismatch", verify_receipt, R["token"], KEYS, tampered, R["valid_at"])

    def test_expired_forged_and_malformed_receipts_are_refused(self):
        self.assert_code("expired", verify_receipt, R["token"], KEYS, R["action"], R["expired_at"])
        self.assert_code("not_yet_valid", verify_receipt, R["token"], KEYS, R["action"], 1000)
        self.assert_code("unknown_key", verify_receipt, R["token"], {}, R["action"], R["valid_at"])
        wrong = {R["server_kid"]: R["approver_public_key"]}
        self.assert_code("bad_signature", verify_receipt, R["token"], wrong, R["action"], R["valid_at"])

        body, signature = R["token"].split(".")
        edited = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        edited["expires_at"] = 9_999_999_999
        spliced = b64(json.dumps(edited).encode()) + "." + signature
        self.assert_code("bad_signature", verify_receipt, spliced, KEYS, R["action"], R["valid_at"])
        for junk in ["", ".", "abc", "a.b.c", "!!.??", None, 42]:
            with self.assertRaises(TwoFError):
                verify_receipt(junk, KEYS, R["action"], R["valid_at"])

    def test_pinned_approvers(self):
        payload = verify_receipt(R["token"], KEYS, R["action"], R["valid_at"])
        self.assertEqual(pinned_approvers(payload, {R["approver"]: R["approver_public_key"]}), ["alice"])
        self.assertEqual(pinned_approvers(payload, {R["approver"]: R["server_public_key"]}), [])
        self.assertEqual(pinned_approvers(payload, {}), [])
        moved = dict(payload, challenge="ch_other")
        self.assertEqual(pinned_approvers(moved, {R["approver"]: R["approver_public_key"]}), [])

    def test_authorize_verifies_the_receipt(self):
        client = twof.TwoF("http://x/", "2f_k", KEYS)
        script = [
            {"id": "ch_test", "state": "pending", "approve_url": "http://x/approve/ch_test", "receipt": None},
            {"id": "ch_test", "state": "approved", "receipt": R["token"]},
        ]
        calls = []
        client._request = lambda method, path, body=None: (calls.append((method, path)), script.pop(0))[1]
        real_time = twof.time.time
        twof.time.time = lambda: R["valid_at"]
        try:
            seen = []
            result = client.authorize(R["action"], "k1", on_pending=lambda c: seen.append(c["approve_url"]))
            self.assertTrue(result.authorized)
            self.assertEqual(seen, ["http://x/approve/ch_test"])
            self.assertEqual(calls[0], ("POST", "/v1/challenges"))
            self.assertTrue(calls[1][1].startswith("/v1/challenges/ch_test?wait="))

            script.append({"id": "ch_x", "state": "allowed", "receipt": R["token"]})
            self.assert_code("action_mismatch", client.authorize, R["other_action"], "k2")
            script.append({"id": "ch_y", "state": "rejected", "receipt": None})
            self.assertFalse(client.authorize(R["action"], "k3").authorized)
        finally:
            twof.time.time = real_time


if __name__ == "__main__":
    unittest.main()
