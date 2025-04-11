package main

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"

	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/opencontainers/go-digest"
	"github.com/shizhMSFT/gha/pkg/markdown"
	_ "github.com/shizhMSFT/registry-test/internal/blake3"
	"github.com/shizhMSFT/registry-test/internal/trace"
	"github.com/shizhMSFT/registry-test/internal/version"
	"github.com/urfave/cli/v2"
	"oras.land/oras-go/v2/registry/remote/auth"
)

func init() {
	// Register SHA-384 algorithm, which is not registered by default
	digest.RegisterAlgorithm(digest.SHA384, crypto.SHA384)
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	app := &cli.App{
		Name:      "cryptotest",
		Usage:     "Test crypto agility of registries",
		UsageText: "cryptotest [options]",
		Version:   version.GetVersion(),
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "registry",
				Aliases:  []string{"r"},
				Usage:    "Registry name",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "username",
				Aliases: []string{"u"},
				Usage:   "Username for authentication",
			},
			&cli.StringFlag{
				Name:    "password",
				Aliases: []string{"p"},
				Usage:   "Password for authentication",
			},
			&cli.StringFlag{
				Name:    "identity-token",
				Aliases: []string{"t", "token"},
				Usage:   "Identity token for authentication",
			},
			&cli.BoolFlag{
				Name:  "plain-http",
				Usage: "Use plain HTTP instead of HTTPS",
			},
			&cli.StringFlag{
				Name:  "namespace",
				Usage: "Namespace for the registry",
				Value: "crypto-test",
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "Output file for the test results",
			},
		},
		Action: func(c *cli.Context) error {
			registry := c.String("registry")
			client := &auth.Client{
				Client: &http.Client{
					Transport: trace.NewTransport(http.DefaultTransport),
				},
				Credential: auth.StaticCredential(registry, auth.Credential{
					Username:     c.String("username"),
					Password:     c.String("password"),
					RefreshToken: c.String("identity-token"),
				}),
				Cache:    auth.NewCache(),
				ClientID: "registry-test",
			}
			client.SetUserAgent("registry-test/" + version.GetVersion())
			output := c.App.Writer
			if outPath := c.String("output"); outPath != "" {
				file, err := os.Create(outPath)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer file.Close()
				output = file
			}
			ctx, logger := trace.NewLogger(c.Context, output)
			suite := &TestSuite{
				Context:   ctx,
				Logger:    logger,
				Registry:  c.String("registry"),
				Namespace: c.String("namespace"),
				Client:    client,
				PlainHTTP: c.Bool("plain-http"),
			}
			return runTest(suite, output)
		},
		HideHelpCommand: true,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return app.RunContext(ctx, os.Args)
}

func runTest(suite *TestSuite, out io.Writer) error {
	// Print title
	fmt.Fprintln(out, "# Crypto Agility Test for", suite.Registry)

	// Test cases
	algorithms := []digest.Algorithm{
		digest.SHA256,
		digest.SHA384,
		digest.SHA512,
		digest.BLAKE3,
	}
	var results [][]any
	for name := range suite.Cases() {
		results = append(results, []any{name})
	}
	for _, alg := range algorithms {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "## Test", alg)
		i := 0
		for name, test := range suite.Cases() {
			fmt.Fprintln(out)
			fmt.Fprintln(out, "###", name)
			fmt.Fprintln(out)
			fmt.Fprintln(out, "<details>")
			fmt.Fprintln(out, "<summary>Test logs</summary>")
			fmt.Fprintln(out, "```")
			result := test(alg)
			fmt.Fprintln(out, "```")
			fmt.Fprintln(out, "</details>")
			switch result {
			case TestResultSuccess:
				results[i] = append(results[i], "✅")
				fmt.Fprintln(out, "✅ Passed")
			case TestResultFailure:
				results[i] = append(results[i], "❌")
				fmt.Fprintln(out, "❌ Failed")
			case TestResultNoImplementation:
				results[i] = append(results[i], "⚠️")
				fmt.Fprintln(out, "⚠️ Functionality not implemented")
			}
			i++
		}
	}

	// Print summary
	fmt.Fprintln(out)
	fmt.Fprintln(out, "## Summary")
	tableHeaders := []string{"Test"}
	for _, alg := range algorithms {
		tableHeaders = append(tableHeaders, alg.String())
	}
	table := markdown.NewTable(tableHeaders...)
	for _, result := range results {
		table.AddRow(result...)
	}
	fmt.Fprintln(out)
	return table.Print(out)
}
