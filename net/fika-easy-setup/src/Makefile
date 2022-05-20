all: x86
	@echo "done"

x86:
	cargo build --release

cross: docker
	cross build --target=aarch64-unknown-linux-musl --release

docker:
	docker ps || sudo service docker start

