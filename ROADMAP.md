# revoke-labs-gatekeeper - ROADMAP

> Release Gatekeeper แบบ SLSA L3 + Sigstore - ด่านสุดท้ายก่อน production

## Flow: เซ็น > ฝาก log > สแกน > ตรวจด้วย OPA > ปล่อย

### 1. SEAL - ผนึกหลักฐาน [#14]
**Workflow:** `.github/workflows/governance-v2.yml`
**Output:**
- `sbom.spdx.json` - SBOM
- `provenance.json` + `cosign.bundle.json` + `rekor_entry.json` - Sigstore
- `manifest.json` / `inventory.json` / `evidence_input.json`
- `EVIDENCE_SHA256.log` - hash รวม

### 2. SCAN - สแกนช่องโหว่
- `grype-report.json`
- `GRYPE_COUNT.log`
- `GRYPE_DB_STATUS.json`

### 3. GATE - ด่าน OPA [FIX #5 / PR #15] - GRC-010 / GRC-011
**ไฟล์:** `release_gate.rego`

| GRC | Rule | Check |
|-----|------|-------|
| GRC-010 | Signer Pin | `input.cosign.signer == https://github.com/yinghiy13-collab/revoke-labs-gatekeeper/.github/workflows/governance-v2.yml@refs/heads/main` |
| GRC-011 | Builder Provenance | `startswith(builder_id, "https://github.com/")` |
| GRC-011 | Rekor Transparency | `regex ^https://rekor.sigstore.dev/api/v1/log/entries/[0-9a-f]{80}$` |
| GRC-010 | SBOM Digest | `regex ^[0-9a-f]{64}$` |

`allow = true` เมื่อ `count(deny) == 0`

### 4. ENFORCE - บังคับใช้
**Checker:** `GRC-PROMPT-V1.2-ENFORCER / validate-governance`
- Block merge เข้า `main` ถ้า `OPA_EVAL.log` FAIL
- `main` is protected branch

### Stats
- Open: 2 PR (#14 bot seal, #15 FIX#5)
- Closed: 13 PR
- Total: 15 runs

## Next: GRC-010, GRC-011 Done -> GRC-012: Threshold + Expiry
