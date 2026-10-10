package trust
default allow=false
allow if {input.builder.trusted; input.signer.trusted}