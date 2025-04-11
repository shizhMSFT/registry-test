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
		{"Push Manifest", s.pushManifest},
		{"Push Manifest (no tag)", s.pushManifestNoTag},
		{"Push Manifest (canonical blobs)", s.pushManifestCanonicalBlobs},
		{"Push Manifest (canonical blobs, no tag)", s.pushManifestCanonicalBlobsNoTag},
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
		s.Logger.Errorf("Resolved blob digest mismatch: expected %s, got %s", desc.Digest.String(), resolvedDesc.Digest.String())
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
	if ss.Namespace == "" {
		ss.Namespace = "mount"
	} else {
		ss.Namespace += "/mount"
	}
	repo, err := ss.repository(alg)
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
	// generate descriptor
	configBlob := []byte("{}")
	configDesc := descriptor.FromBytes(blobAlg, ocispec.MediaTypeImageConfig, configBlob)
	fooBlob := []byte("foo")
	fooDesc := descriptor.FromBytes(blobAlg, ocispec.MediaTypeImageLayer, fooBlob)
	barBlob := []byte("bar")
	barDesc := descriptor.FromBytes(blobAlg, ocispec.MediaTypeImageLayer, barBlob)
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
	manifestDesc := descriptor.FromBytes(manifestAlg, manifest.MediaType, manifestBytes)
	s.Logger.Infof("Generated manifest:\n%s", string(manifestBytes))

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

func (s *TestSuite) pushManifest(alg digest.Algorithm) TestResult {
	return s.pushManifestInternal(alg, alg)
}

func (s *TestSuite) pushManifestCanonicalBlobs(alg digest.Algorithm) TestResult {
	return s.pushManifestInternal(alg, digest.Canonical)
}

func (s *TestSuite) pushManifestInternal(manifestAlg, blobAlg digest.Algorithm) TestResult {
	repo, err := s.repository(manifestAlg)
	if err != nil {
		return TestResultFailure
	}

	manifestBytes, manifestDesc, err := s.prepareManifest(repo, blobAlg, manifestAlg)
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

func (s *TestSuite) pushManifestNoTag(alg digest.Algorithm) TestResult {
	return s.pushManifestNoTagInternal(alg, alg)
}

func (s *TestSuite) pushManifestCanonicalBlobsNoTag(alg digest.Algorithm) TestResult {
	return s.pushManifestNoTagInternal(alg, digest.Canonical)
}

func (s *TestSuite) pushManifestNoTagInternal(manifestAlg, blobAlg digest.Algorithm) TestResult {
	repo, err := s.repository(manifestAlg)
	if err != nil {
		return TestResultFailure
	}

	manifestBytes, manifestDesc, err := s.prepareManifest(repo, blobAlg, manifestAlg)
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
