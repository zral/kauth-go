.PHONY: build build-arm64 sqlc migrate-up test deploy

build:
	CGO_ENABLED=0 go build -o bin/kauth ./cmd/kauth

build-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/kauth-arm64 ./cmd/kauth

sqlc:
	sqlc generate

migrate-up:
	go run ./cmd/migrate up

test:
	CGO_ENABLED=0 go test ./...

deploy:
	$(MAKE) build-arm64
	scp bin/kauth-arm64 pi5:/usr/local/bin/kauth
	ssh pi5 "sudo systemctl restart kauth"
