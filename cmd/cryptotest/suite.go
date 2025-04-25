package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/shizhMSFT/registry-test/internal/descriptor"
	"github.com/shizhMSFT/registry-test/internal/trace"
	"github.com/sirupsen/logrus"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

type TestResult int

const (
	TestResultSuccess TestResult = iota
	TestResultFailure
	TestResultNoImplementation
)

type TestCase struct {
	Name string
	Test func(digest.Algorithm) TestResult
}

type TestSuite struct {
	Context   context.Context
	Logger    logrus.FieldLogger
	Registry  string
	Namespace string
	Client    *auth.Client
	PlainHTTP bool
}

func (s *TestSuite) Cases() iter.Seq2[string, func(digest.Algorithm) TestResult] {
	cases := []TestCase{
		{"Push Blob", s.pushBlob},
		{"Resolve Blob", s.resolveBlob},
		{"Pull Blob", s.pullBlob},
		{"Mount Blob", s.mountBlob},
		{"Push Manifest by tag", s.pushManifestByTag},
		{"Push Manifest by digest", s.pushManifestByDigest},
		{"Push Manifest by digest (canonical blobs)", s.pushManifestCanonicalBlobsByDigest},
		{"Push Manifest by digest (mixed blobs)", s.pushManifestMixedBlobsByDigest},
		{"Resolve Manifest with tag", s.resolveManifestWithTag},
		{"Resolve Manifest with digest", s.resolveManifestWithDigest},
		{"Resolve Manifest with digest (canonical blobs)", s.resolveManifestCanonicalBlobsWithDigest},
		{"Resolve Manifest with digest (mixed blobs)", s.resolveManifestMixedBlobsWithDigest},
		{"Pull Manifest by tag", s.pullManifestByTag},
		{"Pull Manifest by digest", s.pullManifestByDigest},
		{"Pull Manifest by digest (canonical blobs)", s.pullManifestCanonicalBlobsByDigest},
		{"Pull Manifest by digest (mixed blobs)", s.pullManifestMixedBlobsByDigest},
	}
	return func(yield func(string, func(digest.Algorithm) TestResult) bool) {
		for _, c := range cases {
			if !yield(c.Name, c.Test) {
				return
			}
		}
	}
}

func (s *TestSuite) pushBlob(alg digest.Algorithm) TestResult {
	repo, err := s.repository(alg)
	if err != nil {
		return TestResultFailure
	}

	// generate descriptor
	blob := []byte("foo")
	desc := descriptor.FromBytes(alg, "", blob)

	// push blob
	if err := repo.Blobs().Push(s.Context, desc, bytes.NewReader(blob)); err != nil {
		s.Logger.Errorf("Error pushing blob: %v", err)
		return TestResultFailure
	}
	s.Logger.Infof("✅ Pushed blob: %s", desc.Digest.String())
	return TestResultSuccess
}

func (s *TestSuite) resolveBlob(alg digest.Algorithm) TestResult {
	repo, err := s.repository(alg)
	if err != nil {
		return TestResultFailure
	}

	// generate descriptor
	blob := []byte("foo")
	desc := descriptor.FromBytes(alg, "", blob)

	// resolve blob
	resolvedDesc, err := repo.Blobs().Resolve(s.Context, desc.Digest.String())
	if err != nil {
		// oras-go does not handle Docker-Content-Digest properly if the digest
		// is not canonical since the registry always returns the canonical
		// digest.
		canonicalDesc := descriptor.FromBytes(digest.Canonical, "", blob)
		if suffix := fmt.Sprintf(
			": invalid response; digest mismatch in Docker-Content-Digest: received %q when expecting %q",
			canonicalDesc.Digest,
			desc.Digest,
		); !strings.HasSuffix(err.Error(), suffix) {
			s.Logger.Errorf("Error resolving blob: %v", err)
			return TestResultFailure
		}
		resp := s.lastResponse()
		resolvedDesc = ocispec.Descriptor{
			MediaType: resp.Header.Get("Content-Type"),
			Digest:    desc.Digest,
			Size:      resp.ContentLength,
		}
	}
	if resolvedDesc.Digest != desc.Digest {
		s.Logger.Errorf("Resolved blob digest mismatch: expected %s, got %s", desc.Digest, resolvedDesc.Digest)
		return TestResultFailure
	}
	if resolvedDesc.Size != desc.Size {
		s.Logger.Errorf("Resolved blob size mismatch: expected %d, got %d", desc.Size, resolvedDesc.Size)
		return TestResultFailure
	}
	s.Logger.Infof(
		"✅ Resolved blob:\n- Media type: %s\n- Digest: %s\n- Size: %d",
		resolvedDesc.MediaType,
		resolvedDesc.Digest.String(),
		resolvedDesc.Size,
	)
	return TestResultSuccess
}

func (s *TestSuite) pullBlob(alg digest.Algorithm) TestResult {
	repo, err := s.repository(alg)
	if err != nil {
		return TestResultFailure
	}

	// generate descriptor
	blob := []byte("foo")
	desc := descriptor.FromBytes(alg, "", blob)

	// pull blob
	rc, err := repo.Blobs().Fetch(s.Context, desc)
	if err != nil {
		s.Logger.Errorf("Error pulling blob: %v", err)
		return TestResultFailure
	}
	defer rc.Close()
	fetched, err := content.ReadAll(rc, desc)
	if err != nil {
		s.Logger.Errorf("Error reading blob: %v", err)
		return TestResultFailure
	}
	if !bytes.Equal(fetched, blob) {
		s.Logger.Errorf("Fetched blob content mismatch: expected %s, got %s", string(blob), string(fetched))
		return TestResultFailure
	}

	s.Logger.Infof("✅ Fetched blob: %s", desc.Digest.String())
	return TestResultSuccess
}

func (s *TestSuite) mountBlob(alg digest.Algorithm) TestResult {
	ss := *s
	repo, err := ss.repository(alg + "-mount")
	if err != nil {
		return TestResultFailure
	}

	// generate descriptor
	blob := []byte("foo")
	desc := descriptor.FromBytes(alg, "", blob)

	// mount blob
	var refSegments []string
	if s.Namespace != "" {
		refSegments = append(refSegments, s.Namespace)
	}
	refSegments = append(refSegments, alg.String())
	fromRepo := strings.Join(refSegments, "/")
	if err := repo.Mount(s.Context, desc, fromRepo, func() (io.ReadCloser, error) {
		return nil, errors.ErrUnsupported
	}); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			s.Logger.Warn("Mount not supported")
			return TestResultNoImplementation
		}
		s.Logger.Errorf("Error mounting blob: %v", err)
		return TestResultFailure
	}
	s.Logger.Infof("✅ Mounted blob: %s", desc.Digest.String())

	// pull mounted blob
	rc, err := repo.Blobs().Fetch(s.Context, desc)
	if err != nil {
		s.Logger.Errorf("Error pulling mounted blob: %v", err)
		return TestResultFailure
	}
	defer rc.Close()
	fetched, err := content.ReadAll(rc, desc)
	if err != nil {
		s.Logger.Errorf("Error reading mounted blob: %v", err)
		return TestResultFailure
	}
	if !bytes.Equal(fetched, blob) {
		s.Logger.Errorf("Fetched mounted blob content mismatch: expected %s, got %s", string(blob), string(fetched))
		return TestResultFailure
	}

	s.Logger.Infof("✅ Fetched mounted blob: %s", desc.Digest.String())
	return TestResultSuccess
}

func (s *TestSuite) prepareManifest(repo *remote.Repository, blobAlg, manifestAlg digest.Algorithm) ([]byte, ocispec.Descriptor, error) {
	return s.prepareManifestInternal(repo, newTestAlgorithms(blobAlg, manifestAlg))
}

func (s *TestSuite) prepareManifestInternal(repo *remote.Repository, alg *testAlgorithms) ([]byte, ocispec.Descriptor, error) {
	// generate descriptor
	configBlob := []byte("{}")
	configDesc := descriptor.FromBytes(alg.Config, ocispec.MediaTypeImageConfig, configBlob)
	fooBlob := []byte("foo")
	fooDesc := descriptor.FromBytes(alg.Layers[0], ocispec.MediaTypeImageLayer, fooBlob)
	barBlob := []byte("bar")
	barDesc := descriptor.FromBytes(alg.Layers[1], ocispec.MediaTypeImageLayer, barBlob)
	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers: []ocispec.Descriptor{
			fooDesc,
			barDesc,
		},
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "   ")
	if err != nil {
		s.Logger.Errorf("Error marshalling manifest: %v", err)
		return nil, ocispec.Descriptor{}, err
	}
	manifestDesc := descriptor.FromBytes(alg.Manifest, manifest.MediaType, manifestBytes)
	s.Logger.Infof("Generated manifest: %s\n%s", manifestDesc.Digest, string(manifestBytes))
	if repo == nil {
		return manifestBytes, manifestDesc, nil
	}

	// push blob
	blobs := repo.Blobs()
	if err := blobs.Push(s.Context, configDesc, bytes.NewReader(configBlob)); err != nil {
		s.Logger.Errorf("Error pushing config blob: %v", err)
		return nil, ocispec.Descriptor{}, err
	}
	if err := blobs.Push(s.Context, fooDesc, bytes.NewReader(fooBlob)); err != nil {
		s.Logger.Errorf("Error pushing blob foo: %v", err)
		return nil, ocispec.Descriptor{}, err
	}
	if err := blobs.Push(s.Context, barDesc, bytes.NewReader(barBlob)); err != nil {
		s.Logger.Errorf("Error pushing blob bar: %v", err)
		return nil, ocispec.Descriptor{}, err
	}

	return manifestBytes, manifestDesc, nil
}

func (s *TestSuite) pushManifestByTag(alg digest.Algorithm) TestResult {
	repo, err := s.repository(alg)
	if err != nil {
		return TestResultFailure
	}

	manifestBytes, manifestDesc, err := s.prepareManifest(repo, alg, alg)
	if err != nil {
		return TestResultFailure
	}

	// push manifest
	tag := "test"
	manifests := repo.Manifests()
	if err := manifests.PushReference(s.Context, manifestDesc, bytes.NewReader(manifestBytes), tag); err != nil {
		// oras-go does not handle Docker-Content-Digest properly if the digest
		// is not canonical since the registry always returns the canonical
		// digest.
		canonicalDesc := descriptor.FromBytes(digest.Canonical, "", manifestBytes)
		if suffix := fmt.Sprintf(
			": invalid response; digest mismatch in Docker-Content-Digest: received %q when expecting %q",
			canonicalDesc.Digest,
			manifestDesc.Digest,
		); !strings.HasSuffix(err.Error(), suffix) {
			s.Logger.Errorf("Error pushing manifest: %v", err)
			return TestResultFailure
		}
	}

	s.Logger.Infof("✅ Pushed manifest: %s", manifestDesc.Digest.String())
	s.Logger.Infof("Pushed manifest with tag: %s", tag)
	return TestResultSuccess
}

func (s *TestSuite) pushManifestByDigest(alg digest.Algorithm) TestResult {
	return s.pushManifestByDigestInternal(newTestAlgorithms(alg, alg))
}

func (s *TestSuite) pushManifestCanonicalBlobsByDigest(alg digest.Algorithm) TestResult {
	return s.pushManifestByDigestInternal(newTestAlgorithms(digest.Canonical, alg))
}

func (s *TestSuite) pushManifestMixedBlobsByDigest(alg digest.Algorithm) TestResult {
	return s.pushManifestByDigestInternal(&testAlgorithms{
		Config:   alg,
		Layers:   [2]digest.Algorithm{alg, digest.Canonical},
		Manifest: alg,
	})
}

func (s *TestSuite) pushManifestByDigestInternal(alg *testAlgorithms) TestResult {
	repo, err := s.repository(alg.Manifest)
	if err != nil {
		return TestResultFailure
	}

	manifestBytes, manifestDesc, err := s.prepareManifestInternal(repo, alg)
	if err != nil {
		return TestResultFailure
	}

	// push manifest
	manifests := repo.Manifests()
	if err := manifests.Push(s.Context, manifestDesc, bytes.NewReader(manifestBytes)); err != nil {
		// oras-go does not handle Docker-Content-Digest properly if the digest
		// is not canonical since the registry always returns the canonical
		// digest.
		canonicalDesc := descriptor.FromBytes(digest.Canonical, "", manifestBytes)
		if suffix := fmt.Sprintf(
			": invalid response; digest mismatch in Docker-Content-Digest: received %q when expecting %q",
			canonicalDesc.Digest,
			manifestDesc.Digest,
		); !strings.HasSuffix(err.Error(), suffix) {
			s.Logger.Errorf("Error pushing manifest: %v", err)
			return TestResultFailure
		}
	}

	s.Logger.Infof("✅ Pushed manifest: %s", manifestDesc.Digest.String())
	return TestResultSuccess
}

func (s *TestSuite) resolveManifestWithTag(alg digest.Algorithm) TestResult {
	repo, err := s.repository(alg)
	if err != nil {
		return TestResultFailure
	}

	// generate descriptor
	_, manifestDesc, err := s.prepareManifest(nil, alg, digest.Canonical)
	if err != nil {
		return TestResultFailure
	}

	// resolve manifest
	tag := "test"
	manifests := repo.Manifests()
	resolvedDesc, err := manifests.Resolve(s.Context, tag)
	if err != nil {
		s.Logger.Errorf("Error resolving manifest: %v", err)
		return TestResultFailure
	}
	if resolvedDesc.MediaType != manifestDesc.MediaType {
		s.Logger.Errorf("Resolved manifest media type mismatch: expected %s, got %s", manifestDesc.MediaType, resolvedDesc.MediaType)
		return TestResultFailure
	}
	if resolvedDesc.Digest != manifestDesc.Digest {
		s.Logger.Errorf("Resolved manifest digest mismatch: expected %s, got %s", manifestDesc.Digest, resolvedDesc.Digest)
		return TestResultFailure
	}
	if resolvedDesc.Size != manifestDesc.Size {
		s.Logger.Errorf("Resolved manifest size mismatch: expected %d, got %d", manifestDesc.Size, resolvedDesc.Size)
		return TestResultFailure
	}
	s.Logger.Infof(
		"✅ Resolved manifest:\n- Media type: %s\n- Digest: %s\n- Size: %d",
		resolvedDesc.MediaType,
		resolvedDesc.Digest.String(),
		resolvedDesc.Size,
	)
	return TestResultSuccess
}

func (s *TestSuite) resolveManifestWithDigest(alg digest.Algorithm) TestResult {
	return s.resolveManifestWithDigestInternal(newTestAlgorithms(alg, alg))
}

func (s *TestSuite) resolveManifestCanonicalBlobsWithDigest(alg digest.Algorithm) TestResult {
	return s.resolveManifestWithDigestInternal(newTestAlgorithms(digest.Canonical, alg))
}

func (s *TestSuite) resolveManifestMixedBlobsWithDigest(alg digest.Algorithm) TestResult {
	return s.resolveManifestWithDigestInternal(&testAlgorithms{
		Config:   alg,
		Layers:   [2]digest.Algorithm{alg, digest.Canonical},
		Manifest: alg,
	})
}

func (s *TestSuite) resolveManifestWithDigestInternal(alg *testAlgorithms) TestResult {
	repo, err := s.repository(alg.Manifest)
	if err != nil {
		return TestResultFailure
	}

	// generate descriptor
	_, manifestDesc, err := s.prepareManifestInternal(nil, alg)
	if err != nil {
		return TestResultFailure
	}

	// resolve manifest
	manifests := repo.Manifests()
	resolvedDesc, err := manifests.Resolve(s.Context, manifestDesc.Digest.String())
	if err != nil {
		s.Logger.Errorf("Error resolving manifest: %v", err)
		return TestResultFailure
	}
	if resolvedDesc.MediaType != manifestDesc.MediaType {
		s.Logger.Errorf("Resolved manifest media type mismatch: expected %s, got %s", manifestDesc.MediaType, resolvedDesc.MediaType)
		return TestResultFailure
	}
	if resolvedDesc.Digest != manifestDesc.Digest {
		s.Logger.Errorf("Resolved manifest digest mismatch: expected %s, got %s", manifestDesc.Digest, resolvedDesc.Digest)
		return TestResultFailure
	}
	if resolvedDesc.Size != manifestDesc.Size {
		s.Logger.Errorf("Resolved manifest size mismatch: expected %d, got %d", manifestDesc.Size, resolvedDesc.Size)
		return TestResultFailure
	}
	s.Logger.Infof(
		"✅ Resolved manifest:\n- Media type: %s\n- Digest: %s\n- Size: %d",
		resolvedDesc.MediaType,
		resolvedDesc.Digest.String(),
		resolvedDesc.Size,
	)
	return TestResultSuccess
}

func (s *TestSuite) pullManifestByTag(alg digest.Algorithm) TestResult {
	repo, err := s.repository(alg)
	if err != nil {
		return TestResultFailure
	}

	// generate descriptor
	manifestBytes, manifestDesc, err := s.prepareManifest(nil, alg, digest.Canonical)
	if err != nil {
		return TestResultFailure
	}

	// pull manifest
	tag := "test"
	manifests := repo.Manifests()
	desc, rc, err := manifests.FetchReference(s.Context, tag)
	if err != nil {
		s.Logger.Errorf("Error pulling manifest: %v", err)
		return TestResultFailure
	}
	defer rc.Close()

	if desc.MediaType != manifestDesc.MediaType {
		s.Logger.Errorf("Fetched manifest media type mismatch: expected %s, got %s", manifestDesc.MediaType, desc.MediaType)
		return TestResultFailure
	}
	if desc.Digest != manifestDesc.Digest {
		s.Logger.Errorf("Fetched manifest digest mismatch: expected %s, got %s", manifestDesc.Digest, desc.Digest)
		return TestResultFailure
	}
	if desc.Size != manifestDesc.Size {
		s.Logger.Errorf("Fetched manifest size mismatch: expected %d, got %d", manifestDesc.Size, desc.Size)
		return TestResultFailure
	}

	fetched, err := content.ReadAll(rc, manifestDesc)
	if err != nil {
		s.Logger.Errorf("Error reading manifest: %v", err)
		return TestResultFailure
	}
	if !bytes.Equal(fetched, manifestBytes) {
		s.Logger.Errorf("Fetched manifest content mismatch: expected %s, got %s", string(manifestBytes), string(fetched))
		return TestResultFailure
	}

	s.Logger.Infof("✅ Fetched manifest: %s", manifestDesc.Digest.String())
	return TestResultSuccess
}

func (s *TestSuite) pullManifestByDigest(alg digest.Algorithm) TestResult {
	return s.pullManifestByDigestInternal(newTestAlgorithms(alg, alg))
}

func (s *TestSuite) pullManifestCanonicalBlobsByDigest(alg digest.Algorithm) TestResult {
	return s.pullManifestByDigestInternal(newTestAlgorithms(digest.Canonical, alg))
}

func (s *TestSuite) pullManifestMixedBlobsByDigest(alg digest.Algorithm) TestResult {
	return s.pullManifestByDigestInternal(&testAlgorithms{
		Config:   alg,
		Layers:   [2]digest.Algorithm{alg, digest.Canonical},
		Manifest: alg,
	})
}

func (s *TestSuite) pullManifestByDigestInternal(alg *testAlgorithms) TestResult {
	repo, err := s.repository(alg.Manifest)
	if err != nil {
		return TestResultFailure
	}

	// generate descriptor
	manifestBytes, manifestDesc, err := s.prepareManifestInternal(nil, alg)
	if err != nil {
		return TestResultFailure
	}

	// pull manifest
	manifests := repo.Manifests()
	rc, err := manifests.Fetch(s.Context, manifestDesc)
	if err != nil {
		s.Logger.Errorf("Error pulling manifest: %v", err)
		return TestResultFailure
	}
	defer rc.Close()

	fetched, err := content.ReadAll(rc, manifestDesc)
	if err != nil {
		s.Logger.Errorf("Error reading manifest: %v", err)
		return TestResultFailure
	}
	if !bytes.Equal(fetched, manifestBytes) {
		s.Logger.Errorf("Fetched manifest content mismatch: expected %s, got %s", string(manifestBytes), string(fetched))
		return TestResultFailure
	}

	s.Logger.Infof("✅ Fetched manifest: %s", manifestDesc.Digest.String())
	return TestResultSuccess
}

func (s *TestSuite) repository(alg digest.Algorithm) (*remote.Repository, error) {
	refSegments := []string{s.Registry}
	if s.Namespace != "" {
		refSegments = append(refSegments, s.Namespace)
	}
	refSegments = append(refSegments, alg.String())
	repo, err := remote.NewRepository(strings.Join(refSegments, "/"))
	if err != nil {
		s.Logger.Errorf("Error creating repository client: %v", err)
		return nil, err
	}
	repo.Client = s.Client
	repo.PlainHTTP = s.PlainHTTP
	return repo, nil
}

func (s *TestSuite) lastResponse() *http.Response {
	return s.Client.Client.Transport.(*trace.Transport).LastResponse()
}

type testAlgorithms struct {
	Config   digest.Algorithm
	Layers   [2]digest.Algorithm
	Manifest digest.Algorithm
}

func newTestAlgorithms(blobAlg, manifestAlg digest.Algorithm) *testAlgorithms {
	return &testAlgorithms{
		Config:   blobAlg,
		Layers:   [2]digest.Algorithm{blobAlg, blobAlg},
		Manifest: manifestAlg,
	}
}
