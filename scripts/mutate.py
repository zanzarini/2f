"""Mutation testing: break one safety check at a time in a copy of the
repository and see whether the test suite notices. A mutant that survives is a
check no test defends. See docs/TESTING.md.

    python3 scripts/mutate.py .                 # every mutant
    python3 scripts/mutate.py . passkey,quorum  # only those whose name matches
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

SRC = os.path.abspath(sys.argv[1])
WORK = os.path.join(tempfile.gettempdir(), 'twof-mutants')
TARGET = os.environ.get('TWOF_MUTANT_TARGET', os.path.join(tempfile.gettempdir(), 'twof-mutants-target'))
CARGO = shutil.which('cargo') or os.path.expanduser('~/.cargo/bin/cargo')
ONLY = sys.argv[2].split(',') if len(sys.argv) > 2 else None

CORE = 'crates/core/src/'
SRV = 'crates/server/src/'
# (what breaks, file, the check, what replaces it)
MUTANTS = [
    ('cosigner counts as a person', CORE + 'policy.rs', 'None => fact.kind != ApproverKind::Cosigner,', 'None => true,'),
    ('quorum ignores who fits', CORE + 'policy.rs', 'if !fits[slots[slot]][person] || tried[person] {', 'if tried[person] {'),
    ('receipt never expires', CORE + 'receipt.rs', 'if now > payload.expires_at {', 'if false {'),
    ('receipt for any action', CORE + 'receipt.rs', 'if !bool::from(expected.as_bytes().ct_eq(payload.action_hash.as_bytes())) {', 'if false {'),
    ('passkey from any origin', CORE + 'passkey.rs', 'if field("origin") != Some(rp.origin.as_str()) {', 'if false {'),
    ('passkey without user check', CORE + 'passkey.rs', 'if flags & FLAG_USER_PRESENT == 0 || flags & FLAG_USER_VERIFIED == 0 {', 'if false {'),
    ('passkey for any challenge', CORE + 'passkey.rs', 'if !bool::from(got.as_slice().ct_eq(challenge)) {', 'if false {'),
    ('duplicate json keys accepted', CORE + 'canonical.rs', 'if out.contains_key(&key) {', 'if false {'),
    ('any signature verifies', CORE + 'keys.rs', 'key.verify_strict(msg, &sig).is_ok()', 'key.verify_strict(msg, &sig).is_ok() || true'),
    ('allow rule without asset', CORE + 'policy.rs', 'if rule.then == Outcome::Allow && looks_at_amount && when.asset.is_none() {', 'if false {'),
    ('velocity cap ignored', CORE + 'policy.rs', 'Some(total) if total <= velocity.max_total => {}', 'Some(_) => {}'),
    ('invisible characters accepted', CORE + 'action.rs', 'if value.chars().any(|c| c.is_control() || deceptive(c)) {', 'if false {'),
    ('no limit of waiting requests', SRV + 'service.rs', 'if waiting >= i64::from(inner.config.max_pending) {', 'if false {'),
    ('decided challenge can be revived', SRV + 'service.rs', 'if row.state == "pending" && self.is_closed(&row.id) {', 'if false {'),
    ('approval on a decided challenge', SRV + 'service.rs', 'if row.state != "pending" {', 'if false {'),
    ('old policy accepted', SRV + 'service.rs', 'if !current {', 'if false {'),
    ('quorum always reached', SRV + 'service.rs', 'if all_satisfied(&requirements, &facts) {', 'if true {'),
    ('anyone may act on any challenge', SRV + 'service.rs', 'if !requirements.iter().any(|r| r.accepts(&fact)) {', 'if false {'),
    ('receipt of another project consumed', SRV + 'service.rs', 'if payload.project != project {', 'if false {'),
    ('api key without seal or grant', SRV + 'service.rs', 'if !in_force || !inner.sealed', 'if false && !inner.sealed'),
    ('receipt reuse after erased mark', SRV + 'service.rs', 'if inner.is_closed(&payload.id) {', 'if false {'),
    ('challenge row without seal', SRV + 'service.rs', 'if !self.sealed(&challenge_fields(row), row.seal.as_deref()) {', 'if false {'),
    ('idempotency key reused for another action', SRV + 'service.rs', 'if existing_hash != action_hash {', 'if false {'),
    ('challenge of another project readable', SRV + 'service.rs', 'if row.project != project_ro {', 'if false {'),
    ('cloned passkey accepted', SRV + 'service.rs', 'passkey::check_counter(stored, received).map_err(|_| denied())?;', 'let _ = stored;'),
    ('planted enrollment accepted', SRV + 'service.rs', 'if now > expires_at || !self.sealed(&fields, seal.as_deref()) {', 'if false {'),
    ('cosigner signs mismatched binding', SRV + 'cosigner.rs', 'if binding.v != 1 || binding.action_hash != action.hash_hex()? {', 'if false {'),
    ('cosigner accepts unsigned webhook', SRV + 'cosigner.rs', 'if !webhook::verify(&self.server_key, body.as_bytes(), signature) {', 'if false {'),
    ('log may be cut or rewritten', SRV + 'service.rs', 'if !audit::follows(previous, &entry) {', 'if false {'),
    ('log entries need no signature', SRV + 'service.rs', 'if !known && !audit::entry_signature_valid(&self.public, &entry.hash, &sig) {', 'if false {'),
    ('no rate limit', SRV + 'limit.rs', 'if *tokens >= 1.0 {', 'if true {'),
    ('action text may differ from its hash', SRV + 'service.rs', 'if action.hash_hex().map_err(|_| tampered())? != row.action_hash {', 'if false {'),
    ('passkey for another site id', CORE + 'passkey.rs', 'if !bool::from(data[..32].ct_eq(expected_rp.as_slice())) {', 'if false {'),
    ('passkey response of the wrong type', CORE + 'passkey.rs', 'if field("type") != Some(expected_type) {', 'if false {'),
    ('passkey with any algorithm or key', CORE + 'passkey.rs', 'if algorithm != ALG_ES256 || !valid_public_key(spki_der) {', 'if false {'),
    ('passkey counter may stand still', CORE + 'passkey.rs', 'if (stored != 0 || received != 0) && received <= stored {', 'if false {'),
    ('receipt from the future', CORE + 'receipt.rs', 'if payload.issued_at > now.saturating_add(CLOCK_SKEW) {', 'if false {'),
    ('receipt of unknown version', CORE + 'receipt.rs', 'if payload.v != 1 {', 'if false {'),
    ('audit chain link unchecked', CORE + 'audit.rs', 'if entry.prev != expected_prev {', 'if false {'),
    ('audit entry content unchecked', CORE + 'audit.rs', 'if recomputed != entry.hash {', 'if false {'),
    ('audit sequence unchecked', CORE + 'audit.rs', 'if entry.seq != expected_seq {', 'if false {'),
    ('rule ignores the operation type', CORE + 'policy.rs', 'if !kinds.contains(&action.kind) {', 'if false {'),
    ('rule ignores the upper amount', CORE + 'policy.rs', 'if when.amount_max.is_some_and(|max| amount > max) {', 'if false {'),
    ('rule ignores the lower amount', CORE + 'policy.rs', 'if when.amount_min.is_some_and(|min| amount < min) {', 'if false {'),
    ('rule ignores the destination list', CORE + 'policy.rs', 'if !known {', 'if false {'),
    ('amount with leading zeros', CORE + 'action.rs', "if int.len() > 1 && int.starts_with('0') {", 'if false {'),
    ('requirement count unlimited', CORE + 'policy.rs', 'if req.count == 0 || req.count > MAX_COUNT {', 'if false {'),
    ('empty requirement list satisfied', CORE + 'policy.rs', 'if requirements.is_empty() {\n        return false;\n    }', ''),
    ('stored approvals not verified', SRV + 'service.rs', 'if !self.remembered(&digest) {', 'if false {'),
    ('log shorter than a checkpoint', SRV + 'service.rs', 'if vouched.is_some_and(|(at, _)| at > ledger.seq) {', 'if false {'),
    ('log differs from a checkpoint', SRV + 'service.rs', 'if entry.seq == *at && entry.hash != *expected {', 'if false {'),
    ('writer accepts a shorter log', SRV + 'service.rs', 'if !latest && ledger.recent.iter().any(|(s, h)| *s == seq && *h == hash) {', 'if ledger.recent.iter().any(|(s, h)| *s == seq && *h == hash) {'),
    ('planted notifications are sent', SRV + 'delivery.rs', 'if !service.outbox_authentic(&item) {', 'if false {'),
    ('cosigner accepts old webhooks', SRV + 'cosigner.rs', 'if now.abs_diff(ts) > webhook::MAX_AGE {', 'if false {'),
    ('cosigner signs expired challenges', SRV + 'cosigner.rs', 'if binding.expires_at <= now {', 'if false {'),
    ('terminal approver trusts the server hash', SRV + 'device.rs', 'if binding.v != 1 || binding.challenge != challenge || binding.action_hash != action_hash {', 'if false {'),
    ('renamed project shown as is', SRV + 'service.rs', 'if self.sealed(&name_fields(project, &name), seal.as_deref()) {', 'if true {'),
    ('credential not checked against the log', SRV + 'service.rs', '|| !inner.granted(&credential, &row.project, &approver, &kind_text, &public_key)', ''),
    ('stored credential not checked against the log', SRV + 'service.rs', '|| !self.granted(', '|| false && !self.granted('),
    ('audit: challenges not compared', SRV + 'service.rs', 'if stored.challenges != expected.challenges {', 'if false {'),
    ('audit: credentials not compared', SRV + 'service.rs', 'if stored.credentials != expected.credentials {', 'if false {'),
    ('audit: api keys not compared', SRV + 'service.rs', 'if stored.api_keys != expected.api_keys {', 'if false {'),
    ('audit: used receipts not compared', SRV + 'service.rs', 'if stored.consumed != expected.consumed {', 'if false {'),
    ('audit: policies not compared', SRV + 'service.rs', 'if stored.policies != expected.policies {', 'if false {'),
    ('audit: entry signatures not checked', SRV + 'service.rs', 'if !audit::entry_signature_valid(public, &entry.hash, sig) {', 'if false {'),
    ('overdue challenge still approvable', SRV + 'service.rs', 'return Err(Error::Conflict("challenge is expired".into()));', '{}'),
    ('receipt memory skipped on consume', SRV + 'service.rs', 'inner.close(&payload.id, payload.expires_at, now);', ''),
    ('outbox item seal unchecked', SRV + 'service.rs', 'pub fn outbox_authentic(&self, item: &OutboxItem) -> bool {', 'pub fn outbox_authentic(&self, item: &OutboxItem) -> bool {\n        return true;'),
    ('no auth on challenge creation', SRV + 'http.rs', 'let mut map = object(&body, &["action", "idempotency_key"])?;', 'let _ = &project; let project = String::new(); let mut map = object(&body, &["action", "idempotency_key"])?;'),
]


def copy_tree():
    if os.path.exists(WORK):
        shutil.rmtree(WORK)
    shutil.copytree(SRC, WORK, ignore=shutil.ignore_patterns('target', '.git', 'node_modules', '__pycache__'))
    # Fresh timestamps, or cargo may reuse what it built from an earlier copy.
    for folder, _, files in os.walk(WORK):
        for name in files:
            os.utime(os.path.join(folder, name))


def run_tests(extra):
    env = dict(os.environ, CARGO_TARGET_DIR=TARGET)
    command = [CARGO, 'test', '--workspace', '--quiet', '--'] + extra
    done = subprocess.run(command, cwd=WORK, env=env, capture_output=True, text=True)
    return done.returncode == 0, done.stdout + done.stderr


copy_tree()
ok, out = run_tests(['--skip', 'random_operations', '--skip', 'nothing_written_into'])
print('baseline (unmutated):', 'passes' if ok else 'FAILS', flush=True)
if not ok:
    print(out[-2000:])
    sys.exit(1)

survivors = []
for name, path, old, new in MUTANTS:
    if ONLY and not any(word in name for word in ONLY):
        continue
    full = os.path.join(WORK, path)
    original = open(full, encoding='utf-8').read()
    if original.count(old) != 1:
        print(f'SKIPPED   {name}: pattern found {original.count(old)} times', flush=True)
        continue
    open(full, 'w', encoding='utf-8', newline='\n').write(original.replace(old, new))
    started = time.time()
    caught, out = run_tests(['--skip', 'random_operations', '--skip', 'nothing_written_into'])
    caught = not caught
    by = 'the test suite'
    if not caught:
        passed, out = run_tests(['random_operations_agree'])
        caught = not passed
        by = 'the random model only'
        if not caught:
            passed, out = run_tests(['nothing_written_into'])
            caught = not passed
            by = 'the random adversary only'
    open(full, 'w', encoding='utf-8', newline='\n').write(original)
    if 'error[' in out or 'could not compile' in out:
        print(f'BROKEN    {name}: does not compile', flush=True)
        continue
    if caught:
        print(f'caught    {name}  (by {by}, {time.time() - started:.0f}s)', flush=True)
    else:
        survivors.append(name)
        print(f'SURVIVED  {name}', flush=True)

print(f'\n{len(survivors)} survivor(s): {survivors}', flush=True)
