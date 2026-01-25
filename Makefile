PROTOC_CMD = protoc
PROTOC_ARGS = --proto_path=./api/v1/ --go_opt=paths=source_relative --go_out=./go/v1/ --go-grpc_out=./go/v1/ ./api/v1/hauth.proto

LYNKAPI_FILTER_TAG_FIX_CMD = lynkapi-fitter
LYNKAPI_FILTER_TAG_FIX_ARGS = go/v1/hauth.pb.go


all: go-v1
	@echo ""
	@echo "build complete"
	@echo ""

go-v1:
	$(PROTOC_CMD) $(PROTOC_ARGS)
	$(LYNKAPI_FILTER_TAG_FIX_CMD) $(LYNKAPI_FILTER_TAG_FIX_ARGS)

