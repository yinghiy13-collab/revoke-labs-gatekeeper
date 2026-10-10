package release_gate

import future.keywords.in
import future.keywords.contains

default allow := false

# ---- GRC-010: Signer Pin + SBOM Digest + Artifact Binding ----
grc_010 if {
    input.signer_pinned == true
    input.signer == "https://github.com/yinghiy13-collab/revoke-labs-gatekeeper/.github/workflows/governance-v2.yml@refs/heads/main"
    input.sbom_digest_verified == true
    input.sbom_digest == input.expected_sbom_digest
    input.artifact_digest != ""
    input.sbom_artifact_digest == input.artifact_digest
}

# ---- GRC-011: Builder + Rekor Transparency ----
grc_011 if {
    input.builder_id != ""
    input.builder_id == input.expected_builder_id
    input.rekor_entry_verified == true
    input.rekor_log_integrity == true
    input.rekor_inclusion_proof_verified == true
}

# ---- GRC-012: Threshold >=2 + Expiry 7d ----
grc_012 if {
    count(input.signers) >= 2
    input.expiry_days > 0
    input.expiry_days <= 7
    input.threshold_enforced == true
}

# ---- GRC-013: Cosign + OPA + Evidence + Grype 0 ----
grc_013 if {
    input.cosign_bundle_verified == true
    input.cosign_identity_regex_verified == true
    input.cosign_issuer == "https://token.actions.githubusercontent.com"
    input.opa_eval == "PASS"
    input.opa_test_v == "PASS"
    input.evidence_sha256_exists == true
    input.evidence_sha256_verified == true
    input.grype_critical == 0
    input.grype_count_verified == true
}

# ---- SLSA L3 + Sigstore - Bound to artifact ----
slsa_l3_verified if {
    input.provenance_verified == true
    input.provenance_builder_id == input.builder_id
    input.provenance_artifact_digest == input.artifact_digest
    input.slsa_level == "SLSA_L3"
    input.sigstore_verified == true
}

# ---- FINAL GATE: AND - ทุก GRC ต้องผ่านพร้อมกัน ----
allow if {
    grc_010
    grc_011
    grc_012
    grc_013
    slsa_l3_verified
}

# ---- DENY MESSAGES ครบทุก GRC ----
deny contains msg if {
    not grc_010
    msg := "GRC-010 FAILED: Signer pin or SBOM digest mismatch or artifact not bound"
}

deny contains msg if {
    not grc_011
    msg := "GRC-011 FAILED: Builder or Rekor transparency not verified"
}

deny contains msg if {
    not grc_012
    msg := "GRC-012 FAILED: Threshold <2 or Expiry >7d"
}

deny contains msg if {
    not grc_013
    msg := "GRC-013 FAILED: Cosign/OPA/Evidence/Grype verification failed"
}

deny contains msg if {
    not slsa_l3_verified
    msg := "SLSA_L3/Sigstore FAILED: Attestation not verified or not bound to artifact"
}
