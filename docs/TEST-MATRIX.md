# SecureHealth — Test & Validation Matrix

Owner: Cinderella. Maps every automated test to the STRIDE threat it validates
and the control that mitigates it. This is the evidence for the *Testing &
Validation* section of the report.

## How to run

```bash
cd backend

# Unit / logic layer — no AWS needed, runs anywhere
pytest tests/ -q

# Integration layer — real API, real Cognito, real KMS
python get_tokens.py        # sign in as all three roles
source .test-env            # Git Bash / macOS / Linux
pytest tests/test_integration.py -v

# Everything, with STRIDE category visible
pytest tests/ -v -m "stride"
```

Integration tests skip themselves automatically when tokens are absent, so the
unit suite runs unattended.

## Coverage summary

| Layer | File | Tests | What it proves |
|---|---|---|---|
| Validation | `test_validation.py` | 45 | Malicious input never reaches storage |
| Crypto & integrity | `test_encryption_integrity.py` | 17 | PHI is unreadable at rest; tampering is detected |
| Access control | `test_access_control.py` | 33 | Identity cannot be forged; RBAC is deny-by-default |
| Handler pipeline | `test_handlers.py` | 20 | The whole request flow behaves correctly end to end |
| Integration | `test_integration.py` | 30 | The deployed system enforces all of the above |

**115 unit tests pass offline in under a second; 30 integration tests run against the live API.**

STRIDE distribution across marked tests: Tampering 32, Information Disclosure 22,
Elevation of Privilege 17, Repudiation 10, Spoofing 7, Denial of Service 3.

## Threat → test matrix

### S — Spoofing (identity)

| Threat | Test | Control |
|---|---|---|
| Unauthenticated caller reaches PHI | `test_unauthenticated_request_is_rejected` | API Gateway Cognito authorizer (401 before Lambda runs) |
| Forged or `alg:none` JWT accepted | `test_forged_tokens_are_rejected` | Authorizer verifies signature, issuer, audience, expiry |
| Identity injected via header or body | `test_headers_and_body_cannot_set_identity` | Identity read only from validated `cognito:groups` claim |
| Missing authorizer context defaults to a role | `test_missing_authorizer_context_yields_no_role` | Returns `None` → deny |
| Attacker invents a group name | `test_unrecognised_group_yields_no_role` | Role must match a known group |
| Stolen password alone grants access | (manual) MFA enrolment required at sign-in | Cognito MFA enforced, 12-char policy, lockout |

### T — Tampering (data integrity)

| Threat | Test | Control |
|---|---|---|
| SQL/NoSQL injection via form fields | `test_injection_payloads_rejected` (7 payloads, unit + integration) | Server-side whitelist validation |
| XSS stored in a record | `test_xss_payloads_rejected` (5 payloads) | Character whitelist on names |
| XSS reflected through an error message | `test_error_message_never_echoes_the_payload` | Errors name the field, never the value |
| Record edited directly in the database | `test_tamper_with_plaintext_field_is_detected`, `test_tampered_record_returns_409` | SHA-256 verified on every read |
| Encrypted blob swapped | `test_tamper_with_ciphertext_is_detected` | Hash covers decrypted plaintext |
| Integrity hash forged alongside the edit | `test_forged_integrity_hash_is_detected` | Hash recomputed server-side, never accepted from client |
| Integrity hash deleted | `test_missing_integrity_hash_is_detected` | Absent hash fails verification |
| Subtle change (case, dosage) slips through | `test_hash_is_case_sensitive` | Byte-exact comparison |
| Path traversal in the record id | `test_invalid_patient_ids_rejected`, `test_path_traversal_id_rejected` | Strict UUIDv4 pattern |
| Stale hash after a legitimate edit | `test_update_rehashes_and_reencrypts` | Re-encrypt and re-hash on every write |
| Invalid dates / health cards stored | `test_invalid_dates_rejected`, `test_health_card_must_be_ten_digits` | Field-level format rules |

### R — Repudiation (accountability)

| Threat | Test | Control |
|---|---|---|
| User denies viewing or changing a record | `test_audit_entry_records_who_what_when`, `test_actions_appear_in_audit_log` | Append-only audit log with user, role, action, time |
| Denied attempts leave no trace | `test_denied_attempts_are_audited`, `test_denied_attempts_appear_in_audit_log` | Denials are audited, not just successes |
| Attack attempts leave no trace | `test_validation_rejections_are_audited` | Rejections logged with the reason |
| Tampering goes unnoticed | `test_tamper_detection_is_audited` | `TAMPER_DETECTED` event + CloudWatch alert line |
| Audit reads themselves unlogged | `test_audit_read_is_itself_audited` | Reading the log is an audited action |
| Concurrent events overwrite each other | `test_audit_entries_have_unique_sort_keys` | Timestamp + random suffix sort key |

### I — Information Disclosure (confidentiality)

| Threat | Test | Control |
|---|---|---|
| PHI readable from a stolen table or backup | `test_clinical_fields_are_not_stored_in_plaintext` | AES-256-GCM via KMS + table encryption at rest |
| Ciphertext moved between patients | `test_ciphertext_bound_to_its_patient` | Per-record encryption context |
| Receptionist reads clinical data | `test_receptionist_sees_redacted_clinical_fields` (unit + integration) | Server-side field redaction by role |
| Redaction leaks via search results | `test_search_redacts_for_receptionist` | Redaction applied to every response path |
| Interception in transit | `test_transport_is_https_only`, `test_security_headers_present` | TLS 1.2+, HSTS, `nosniff`, `DENY`, `no-store` |
| Stack traces or ARNs in error bodies | `test_error_body_has_no_internal_detail`, `test_errors_do_not_leak_internals` | Generic client errors; detail to CloudWatch only |
| Username enumeration at login | (manual) generic "Incorrect username or password" | Identical message for unknown user and bad password |

### D — Denial of Service (availability)

| Threat | Test | Control |
|---|---|---|
| Oversized payload exhausts the function | `test_oversized_body_rejected`, `test_oversized_field_rejected` | 10 KB body cap, per-field length caps |
| Unbounded audit query | `test_audit_limit_is_capped` | Server clamps `limit` to 200 |
| Request flooding | (manual) API Gateway throttling 20 req/s, burst 40 | Per-method throttling |
| One corrupt record breaks the whole list | `test_search_skips_and_counts_tampered_records` | Bad records skipped and counted, not fatal |

### E — Elevation of Privilege (authorization)

| Threat | Test | Control |
|---|---|---|
| Receptionist creates or edits records | `test_receptionist_cannot_create`, `test_receptionist_cannot_update_patient` | Deny-by-default RBAC in Lambda |
| Non-admin reads the audit trail | `test_doctor_cannot_read_audit_log`, `test_only_admin_reads_audit_log` | `audit:read` restricted to Admin |
| Roleless account gets default access | `test_user_without_role_cannot_create` | No role → 403 |
| Mass assignment (`is_admin`, `role`) | `test_unknown_and_server_managed_fields_rejected`, `test_mass_assignment_rejected` | Unknown fields rejected outright |
| Client chooses its own record id | `test_client_cannot_set_patient_id` | `patient_id` is server-generated |
| New action defaults to allowed | `test_unknown_action_is_denied_by_default` | Permission matrix is an allowlist |
| UI-only enforcement bypassed via API | `test_receptionist_cannot_create_patient` (integration) | Every control enforced server-side |

## Manual test scenarios (demo script)

Automated coverage aside, these are performed live in the presentation:

1. **Unauthenticated call** → `curl /health` with no token → 401.
2. **MFA login** → password alone is insufficient; TOTP required.
3. **Role comparison** → same record as `doctor1` (full) and `reception1` (`[REDACTED]`).
4. **UI is not the control** → `reception1` has no "New patient" tab *and* a direct
   API POST returns 403.
5. **Encryption at rest** → DynamoDB console shows `clinical_notes_enc` ciphertext,
   never the plaintext note.
6. **Tamper detection** → edit `first_name` in the console → read returns 409, record
   withheld from search with a banner, `TAMPER_DETECTED` in the audit log →
   restore the value → record verifies again.
7. **Audit trail** → Admin-only tab showing every action, including all denials.

## Known gaps (state these rather than hide them)

- Rate limiting is verified by configuration review, not by a load test.
- Cognito lockout and MFA enrolment are exercised manually, not in CI.
- No fuzzing campaign; validation is tested against a curated payload set.
- Integration tests create records and do not delete them (no delete endpoint
  exists by design), so the demo dataset grows with each run.
