// Command aiproxy is the entry point for the aiproxy CLI.
package main

import (
	"os"

	"aiproxy/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
