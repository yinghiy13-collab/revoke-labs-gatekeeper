package sovern.release
import future.keywords.every
import future.keywords.if
default allow := false
required_gates := {"G01","G02","G03","G04","G05","G06","G07","G08","G09","G10","G11","G12"}
required_files := {"sbom.spdx.json","provenance.json","cosign.bundle.json","rekor_entry.json","grype-report.json"}
present := {g.id | some g in input.gates}
present_files := {f.name | some f in input.evidence_files}
grype_db_fresh if {
  input.grype_db.built
  now := time.now_ns()
  built := time.parse_rfc3339_ns(input.grype_db.built)
  age_hours := (now - built) / (1000000000*3600)
  age_hours <= 120
}
valid_identity if {
  input.attestations.signer_identity
  regex.match(`^https://github.com/yinghiy13-collab/`, input.attestations.signer_identity)
  input.attestations.oidc_issuer == "https://token.actions.githubusercontent.com"
}
valid_provenance if {
  input.attestations.slsa_v1 == true
  input.attestations.builder_id
  contains(input.attestations.builder_id, "github.com")
}
allow if {
  required_gates == present
  every g in input.gates { g.status == "PASS" }
  input.vulnerabilities.critical == 0
  input.vulnerabilities.high == 0
  input.attestations.cosign_verified == true
  input.attestations.rekor_entry!= ""
  regex.match(`^https://rekor.sigstore.dev/api/v1/log/entries/[a-f0-9]+$`, input.attestations.rekor_entry)
  valid_identity
  valid_provenance
  grype_db_fresh
  required_files == {f | some f in present_files; f in required_files}
  count(present_files) >= 5
  every f in input.evidence_files { f.digest!= ""; regex.match("^[a-f0-9]{64}$", f.digest) }
  input.sbom.valid == true
}
