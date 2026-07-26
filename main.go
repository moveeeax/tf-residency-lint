package main

import (
	"fmt"
	"os"

	"github.com/moveeeax/tf-residency-lint/cmd"
)

func main() {
	code, err := cmd.Run(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tf-residency-lint:", err)
	}
	os.Exit(code)
}
