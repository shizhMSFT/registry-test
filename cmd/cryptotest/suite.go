package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"iter"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/shizhMSFT/registry-test/internal/descriptor"
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
		s.Logger.Errorf("❌ Error pushing blob: %v", err)
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
		s.Logger.Errorf("❌ Error resolving blob: %v", err)
		return TestResultFailure
	}
	if resolvedDesc.Digest != desc.Digest {
		s.Logger.Errorf("❌ Resolved blob digest mismatch: expected %s, got %s", desc.Digest.String(), resolvedDesc.Digest.String())
		return TestResultFailure
	}
	if resolvedDesc.Size != desc.Size {
		s.Logger.Errorf("❌ Resolved blob size mismatch: expected %d, got %d", desc.Size, resolvedDesc.Size)
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
		s.Logger.Errorf("❌ Error pulling blob: %v", err)
		return TestResultFailure
	}
	defer rc.Close()
	fetched, err := content.ReadAll(rc, desc)
	if err != nil {
		s.Logger.Errorf("❌ Error reading blob: %v", err)
		return TestResultFailure
	}
	if !bytes.Equal(fetched, blob) {
		s.Logger.Errorf("❌ Fetched blob content mismatch: expected %s, got %s", string(blob), string(fetched))
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
			s.Logger.Infof("⚠️ Mount not supported: %v", err)
			return TestResultNoImplementation
		}
		s.Logger.Errorf("❌ Error mounting blob: %v", err)
		return TestResultFailure
	}
	s.Logger.Infof("✅ Mounted blob: %s", desc.Digest.String())

	// pull mounted blob
	rc, err := repo.Blobs().Fetch(s.Context, desc)
	if err != nil {
		s.Logger.Errorf("❌ Error pulling mounted blob: %v", err)
		return TestResultFailure
	}
	defer rc.Close()
	fetched, err := content.ReadAll(rc, desc)
	if err != nil {
		s.Logger.Errorf("❌ Error reading mounted blob: %v", err)
		return TestResultFailure
	}
	if !bytes.Equal(fetched, blob) {
		s.Logger.Errorf("❌ Fetched mounted blob content mismatch: expected %s, got %s", string(blob), string(fetched))
		return TestResultFailure
	}

	s.Logger.Infof("✅ Fetched mounted blob: %s", desc.Digest.String())
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
		s.Logger.Errorf("❌ Error creating repository client: %v", err)
		return nil, err
	}
	repo.Client = s.Client
	repo.PlainHTTP = s.PlainHTTP
	return repo, nil
}
