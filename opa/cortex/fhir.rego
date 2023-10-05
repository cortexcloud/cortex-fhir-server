package cortex.fhir

import future.keywords.if

default allow := false

allow if {
	jwt_verified
}

jwt_payload = payload if {
	[_, payload, _] := io.jwt.decode(input.token)
}

now := time.now_ns()

jwt_verified if {
	jwks := json.marshal(data.jwks)
	# Check signature
	io.jwt.verify_rs256(input.token, jwks)
	# Check expire time
	jwt_payload.exp * 1000 * 1000 * 1000 > now
}