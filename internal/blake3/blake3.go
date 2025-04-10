package blake3

import (
	"hash"

	"github.com/opencontainers/go-digest"
	"github.com/zeebo/blake3"
)

func init() {
	digest.RegisterAlgorithm(digest.BLAKE3, &blake3hash{})
}

type blake3hash struct{}

func (blake3hash) Available() bool {
	return true
}

func (blake3hash) Size() int {
	return blake3.New().Size()
}

func (blake3hash) New() hash.Hash {
	return blake3.New()
}
