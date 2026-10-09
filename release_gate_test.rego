package sovern.release
d := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
ids := ["G01","G02","G03","G04","G05","G06","G07","G08","G09","G10","G11","G12"]
files := ["sbom.spdx.json","provenance.json","cosign.bundle.json","rekor_entry.json","grype-report.json"]
valid := {
  "gates": [{"id": i, "status": "PASS"} | some i in ids],
  "vulnerabilities": {"critical": 0, "high": 0},
  "attestations": {
    "slsa_v1": true, "cosign_verified": true,
    "rekor_entry": "https://rekor.sigstore.dev/api/v1/log/entries/abc123",
    "signer_identity": "https://github.com/yinghiy13-collab/revoke-labs-gatekeeper/.github/workflows/gate-offline.yml@refs/heads/main",
    "oidc_issuer": "https://token.actions.githubusercontent.com",
    "builder_id": "https://github.com/actions/runner"
  },
  "grype_db": {"built": "2026-10-09T00:00:00Z"},
  "sbom": {"valid": true},
  "evidence_files": [{"name": n, "digest": d} | some n in files],
}
test_allow_valid if { allow with input as valid }
test_deny_high_vuln if { not allow with input as json.patch(valid, [{"op":"replace","path":"/vulnerabilities/high","value":1}]) }
test_deny_gate_not_run if { not allow with input as json.patch(valid, [{"op":"replace","path":"/gates/11/status","value":"NOT_RUN"}]) }
test_deny_missing_gate if { not allow with input as json.patch(valid, [{"op":"remove","path":"/gates/11"}]) }
test_deny_missing_file if { not allow with input as json.patch(valid, [{"op":"remove","path":"/evidence_files/4"}]) }
test_deny_bad_digest if { not allow with input as json.patch(valid, [{"op":"replace","path":"/evidence_files/0/digest","value":"xyz"}]) }
test_deny_bad_rekor if { not allow with input as json.patch(valid, [{"op":"replace","path":"/attestations/rekor_entry","value":"exists"}]) }
test_deny_slsa_false if { not allow with input as json.patch(valid, [{"op":"replace","path":"/attestations/slsa_v1","value":false}]) }
test_deny_cosign_false if { not allow with input as json.patch(valid, [{"op":"replace","path":"/attestations/cosign_verified","value":false}]) }
test_deny_grype_db_stale if { not allow with input as json.patch(valid, [{"op":"replace","path":"/grype_db/built","value":"2020-01-01T00:00:00Z"}]) }
test_deny_bad_identity if { not allow with input as json.patch(valid, [{"op":"replace","path":"/attestations/signer_identity","value":"https://evil.com"}]) }
