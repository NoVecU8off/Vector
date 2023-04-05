PROTO_DIR = src/proto
PROTO_FILES = $(wildcard $(PROTO_DIR)/*.proto)
PROTO_GEN_DIR = src/proto

PROTOC = protoc
PROTOC_OPTS = --rust_out=$(PROTO_GEN_DIR) --grpc-rust_out=$(PROTO_GEN_DIR) --plugin=protoc-gen-grpc-rust=C:/Users/Mi/.cargo/bin/grpc_rust_plugin.exe

compile:
	$(PROTOC) $(PROTOC_OPTS) $(PROTO_FILES)

clean:
	rm -rf $(PROTO_GEN_DIR)

run:
	cargo run

build:
	cargo build

test:
	cargo test