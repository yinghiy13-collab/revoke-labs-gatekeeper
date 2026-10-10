package release_gate
import data.trust
default allow=false
allow if {trust.allow; input.artifact.digest; input.receipt.present; not input.expired}
