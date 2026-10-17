.PHONY: build testidp build-arm64 sqlc migrate-up test ci deploy

build:
	CGO_ENABLED=0 go build -o bin/kauth ./cmd/kauth

testidp:
	CGO_ENABLED=0 go build -o bin/kauth-testidp ./cmd/kauth-testidp

build-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/kauth-arm64 ./cmd/kauth

sqlc:
	sqlc generate

migrate-up:
	go run ./cmd/migrate up

test:
	CGO_ENABLED=0 go test ./...

# Lokal speiling av CI uten -race og uten nett.
ci:
	@test -z "$$(gofmt -l .)" || (echo "Ikke formatert:"; gofmt -l .; exit 1)
	go vet ./...
	CGO_ENABLED=0 go test ./... -count=1

deploy:
	@test -n "$(KAUTH_DEPLOY_HOST)" || (echo "KAUTH_DEPLOY_HOST må være satt (f.eks. lars@example.com)"; exit 1)
	$(MAKE) build-arm64
	scp bin/kauth-arm64 $(KAUTH_DEPLOY_HOST):/usr/local/bin/kauth
	ssh $(KAUTH_DEPLOY_HOST) "sudo systemctl restart kauth"
