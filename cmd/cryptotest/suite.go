package main

import (
	"context"
	"iter"
	"strings"

	"github.com/opencontainers/go-digest"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

type TestSuite struct {
	Context   context.Context
	Registry  string
	Namespace string
	Client    *auth.Client
	PlainHTTP bool
}

type TestCase struct {
	Name string
	Test func(digest.Algorithm) bool
}

func (s *TestSuite) Cases() iter.Seq2[string, func(digest.Algorithm) bool] {
	cases := []TestCase{}
	return func(yield func(string, func(digest.Algorithm) bool) bool) {
		for _, c := range cases {
			if !yield(c.Name, c.Test) {
				return
			}
		}
	}
}

func (s *TestSuite) repository(alg digest.Algorithm) (registry.Repository, error) {
	repo, err := remote.NewRepository(strings.Join([]string{
		s.Registry,
		s.Namespace,
		alg.String(),
	}, "/"))
	if err != nil {
		return nil, err
	}
	repo.Client = s.Client
	repo.PlainHTTP = s.PlainHTTP
	return repo, nil
}
