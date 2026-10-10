package main
import future.keywords.contains
import future.keywords.if
import future.keywords.in

# FIX #5: pin signer แบบตรงตัว + escape จุด - GRC-010
valid_signer := "https://github.com/yinghiy13-collab/revoke-labs-gatekeeper/.github/workflows/governance-v2.yml@refs/heads/main"

# allow = true เมื่อไม่มี deny
default allow := false
allow if {
  count(deny) == 0
}

# --- GRC-010: Signer Identity ---
deny contains msg if {
  input.cosign.signer != valid_signer
  msg := sprintf("FAIL signer must be %s got %s", [valid_signer, input.cosign.signer])
}

# --- GRC-011: Builder Provenance - ต้องเริ่มด้วย https://github.com/ ---
deny contains msg if {
  not startswith(input.slsa.builder_id, "https://github.com/")
  msg := "FAIL builder_id must startswith https://github.com/"
}

# --- GRC-011: Rekor Transparency - ต้องเป็น URL จริง ---
deny contains msg if {
  not regex.match(`^https://rekor\.sigstore\.dev/api/v1/log/entries/[0-9a-f]{80}$`, input.rekor.entry)
  msg := "FAIL rekor entry invalid"
}

# --- GRC-010: SBOM Digest Integrity - ต้อง 64 hex ---
deny contains msg if {
  not regex.match(`^[0-9a-f]{64}$`, input.sbom.digest)
  msg := "FAIL digest format"
}
