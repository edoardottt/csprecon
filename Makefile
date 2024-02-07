REPO=github.com/edoardottt/csprecon

remod:
	@rm -rf go.*
	@go mod init ${REPO}
	@go get ./...
	@go mod tidy -v
	@echo "Done."

update:
	@go get -u ./...
	@go mod tidy -v
	@echo "Done."

lint:
	@golangci-lint run

linux:
	@go build -o csprecon ./cmd/csprecon
	@sudo mv csprecon /usr/local/bin/
	@echo "Done."

unlinux:
	@sudo rm -rf /usr/local/bin/csprecon
	@echo "Done."

test:
	@go test -race ./...
	@echo "Done."