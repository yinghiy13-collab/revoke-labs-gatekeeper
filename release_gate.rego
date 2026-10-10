package release

import future.keywords.in
import future.keywords.contains

# GRC-010/011/012/013 - SLSA L3 + Sigstore + Threshold + Cosign Verify

default allow = false
allow = true if count(deny) == 0

# ---------- GRC-010: Signer Pin ----------
deny contains msg if {
  input.cosign.signer != "https://github.com/yinghiy13-collab/revoke-labs-gatekeeper/.github/workflows/governance-v2.yml@refs/heads/main"
  msg := sprintf("GRC-010 FAIL: Signer Pin: %v", [input.cosign.signer])
}

# ---------- GRC-010: SBOM Digest ----------
deny contains msg if {
  not regex.match("^[0-9a-f]{64}$", input.sbom.digest)
  msg := sprintf("GRC-010 FAIL: SBOM Digest: %v", [input.sbom.digest])
}

# ---------- GRC-011: Builder ----------
deny contains msg if {
  not startswith(input.builder.builder_id, "https://github.com/")
  msg := sprintf("GRC-011 FAIL: Builder: %v", [input.builder.builder_id])
}

# ---------- GRC-011: Rekor ----------
deny contains msg if {
  not regex.match("^https://rekor.sigstore.dev/api/v1/log/entries/[0-9a-f]{80}$", input.rekor.entry_url)
  msg := sprintf("GRC-011 FAIL: Rekor URL: %v", [input.rekor.entry_url])
}

# ---------- GRC-012: Threshold ----------
deny contains msg if {
  count(input.cosign.signers) < 2
  msg := sprintf("GRC-012 FAIL: Threshold <2 got %v", [count(input.cosign.signers)])
}
deny contains msg if {
  not contains(input.provenance.ref, "refs/heads/main")
  msg := sprintf("GRC-012 FAIL: Only main allowed: %v", [input.provenance.ref])
}

# ---------- GRC-012: Expiry 7d ----------
deny contains msg if {
  (time.now_ns() - time.parse_rfc3339_ns(input.rekor.integrated_time)) > 7*24*60*60*1000000000
  msg := "GRC-012 FAIL: Rekor expired >7d"
}
deny contains msg if {
  input.sbom.generated_at
  (time.now_ns() - time.parse_rfc3339_ns(input.sbom.generated_at)) > 7*24*60*60*1000000000
  msg := "GRC-012 FAIL: SBOM expired >7d"
}

# ---------- GRC-013: Cosign Verification + Policy Audit ----------
deny contains msg if {
  not input.cosign.bundle_verified
  msg := "GRC-013 FAIL: cosign.bundle.json not verified"
}
deny contains msg if {
  input.evidence.opa_eval != "PASS"
  msg := sprintf("GRC-013 FAIL: OPA_EVAL.log != PASS got %v", [input.evidence.opa_eval])
}
deny contains msg if {
  not input.evidence.sha256_log_exists
  msg := "GRC-013 FAIL: EVIDENCE_SHA256.log missing"
}
deny contains msg if {
  input.grype.critical_count > 0
  msg := sprintf("GRC-013 FAIL: GRYPE CRITICAL %v found", [input.grype.critical_count])
}
