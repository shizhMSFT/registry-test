package main

import (
	"fmt"
	"log"
	"os"

	"github.com/shizhMSFT/registry-test/internal/version"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:      "cryptotest",
		Usage:     "Test crypto agility of registries",
		UsageText: "cryptotest [options] {registry}[/{repository}]",
		Version:   version.GetVersion(),
		Action: func(c *cli.Context) error {
			return runTest()
		},
		HideHelpCommand: true,
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func runTest() error {
	fmt.Println("hello world")
	return nil
}
