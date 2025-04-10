package descriptor

import (
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func FromBytes(alg digest.Algorithm, mediaType string, content []byte) ocispec.Descriptor {
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	return ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    alg.FromBytes(content),
		Size:      int64(len(content)),
	}
}
