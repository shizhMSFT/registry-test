package main

import (
	"context"
	"fmt"
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
			ctx, _ := trace.NewLogger(c.Context)
			suite := &TestSuite{
				Context:   ctx,
				Registry:  c.String("registry"),
				Namespace: c.String("namespace"),
				Client:    client,
				PlainHTTP: c.Bool("plain-http"),
			}
			return runTest(suite)
		},
		HideHelpCommand: true,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return app.RunContext(ctx, os.Args)
}

func runTest(suite *TestSuite) error {
	// Print title
	fmt.Println("# Crypto Agility Test for", suite.Registry)

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
		fmt.Println()
		fmt.Println("## Test", alg)
		i := 0
		for name, test := range suite.Cases() {
			fmt.Println()
			fmt.Println("###", name)
			fmt.Println()
			fmt.Println("<details>")
			fmt.Println("<summary>Test logs</summary>")
			result := test(alg)
			fmt.Println("</details>")
			if result {
				results[i] = append(results[i], "✅")
				fmt.Println("✅ Passed")
			} else {
				results[i] = append(results[i], "❌")
				fmt.Println("❌ Failed")
			}
			i++
		}
	}

	// Print summary
	fmt.Println()
	fmt.Println("## Summary")
	tableHeaders := []string{"Test"}
	for _, alg := range algorithms {
		tableHeaders = append(tableHeaders, alg.String())
	}
	table := markdown.NewTable(tableHeaders...)
	for _, result := range results {
		table.AddRow(result...)
	}
	fmt.Println()
	return table.Print(os.Stdout)
}
