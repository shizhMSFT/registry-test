module github.com/shizhMSFT/registry-test

go 1.24.0

require (
	github.com/opencontainers/go-digest v1.0.0
	github.com/shizhMSFT/gha v0.3.0
	github.com/sirupsen/logrus v1.9.3
	github.com/urfave/cli/v2 v2.27.6
	github.com/zeebo/blake3 v0.2.3
	oras.land/oras-go/v2 v2.5.0
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.5 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	golang.org/x/sync v0.6.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
)

replace github.com/opencontainers/go-digest v1.0.0 => github.com/opencontainers/go-digest v0.0.0-20250116041648-1e56c6daea3b
