package release

import future.keywords.in
import future.keywords.contains

# GRC-010 / 011 / 012 - Release Gatekeeper SLSA L3 + Sigstore

default allow = false
allow = true if count(deny) == 0

# ---------- GRC-010: Signer Pin ----------
deny contains msg if {
  input.cosign.signer != "https://github.com/yinghiy13-collab/revoke-labs-gatekeeper/.github/workflows/governance-v2.yml@refs/heads/main"
  msg := sprintf("GRC-010 FAIL: Signer Pin mismatch: got %v", [input.cosign.signer])
}

# ---------- GRC-010: SBOM Digest ----------
deny contains msg if {
  not regex.match("^[0-9a-f]{64}$", input.sbom.digest)
  msg := sprintf("GRC-010 FAIL: SBOM Digest invalid: %v", [input.sbom.digest])
}

# ---------- GRC-011: Builder Provenance ----------
deny contains msg if {
  not startswith(input.builder.builder_id, "https://github.com/")
  msg := sprintf("GRC-011 FAIL: Builder Provenance not 【entity-GitHub¦canonical_name=GitHub】: %v", [input.builder.builder_id])
}

# ---------- GRC-011: Rekor Transparency ----------
deny contains msg if {
  not regex.match("^https://rekor.sigstore.dev/api/v1/log/entries/[0-9a-f]{80}$", input.rekor.entry_url)
  msg := sprintf("GRC-011 FAIL: Rekor Transparency URL invalid: %v", [input.rekor.entry_url])
}

# ---------- GRC-012: Threshold ----------
# ต้องมี signer อย่างน้อย 2 คน
deny contains msg if {
  count(input.cosign.signers) < 2
  msg := sprintf("GRC-012 FAIL: Threshold require >=2 signers, got %v", [count(input.cosign.signers)])
}

# ต้องมาจาก main เท่านั้น
deny contains msg if {
  not contains(input.provenance.ref, "refs/heads/main")
  msg := sprintf("GRC-012 FAIL: Only refs/heads/main allowed, got %v", [input.provenance.ref])
}

# ---------- GRC-012: Expiry ----------
# Rekor entry ต้องไม่เกิน 7 วัน
deny contains msg if {
  now := time.now_ns()
  integrated := time.parse_rfc3339_ns(input.rekor.integrated_time)
  (now - integrated) > 7*24*60*60*1000000000
  msg := "GRC-012 FAIL: Rekor entry expired >7d"
}

# SBOM ต้องไม่เกิน 7 วัน (ถ้ามี timestamp)
deny contains msg if {
  input.sbom.generated_at
  now := time.now_ns()
  gen := time.parse_rfc3339_ns(input.sbom.generated_at)
  (now - gen) > 7*24*60*60*1000000000
  msg := "GRC-012 FAIL: SBOM expired >7d"
}
