.PHONY: all, clean

all: bbs

bbs: cmd/bbs.go
	go build -o bbs cmd/bbs.go


clean:
	rm -rf bbs