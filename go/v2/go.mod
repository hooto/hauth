module github.com/hooto/hauth/go/v2

go 1.25.6

require (
	github.com/google/uuid v1.6.0
	github.com/hooto/hauth/go v0.1.5
	google.golang.org/grpc v1.78.0
)

require (
	github.com/hooto/htoml4g v0.9.5 // indirect
	golang.org/x/sys v0.40.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/hooto/hauth/go => ../v1
