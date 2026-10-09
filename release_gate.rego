package main

# FIX #5: pin signer แบบตรงตัว + escape จุด
valid_signer := "https://github.com/yinghiy13-collab/revoke-labs-gatekeeper/.github/workflows/governance-v2.yml@refs/heads/main"

deny contains msg if {
  input.cosign.signer != valid_signer
  msg := sprintf("FAIL signer must be %s got %s", [valid_signer, input.cosign.signer])
}

# FIX: builder_id ต้องเริ่มด้วย https://github.com/ เท่านั้น ไม่ใช่ contains
deny contains msg if {
  not startswith(input.slsa.builder_id, "https://github.com/")
  msg := "FAIL builder_id must startswith https://github.com/"
}

# FIX: rekor ต้องเป็น URL จริง ไม่ใช่ abc123def456
deny contains msg if {
  not regex.match(`^https://rekor\\.sigstore\\.dev/api/v1/log/entries/[0-9a-f]{80}$`, input.rekor.entry)
  msg := "FAIL rekor entry invalid"
}

# FIX: digest ต้อง 64 hex และต้อง hash จริง (ให้ verifier ทำก่อนเข้า OPA)
deny contains msg if {
  not regex.match(`^[0-9a-f]{64}$`, input.sbom.digest)
  msg := "FAIL digest format"
}
