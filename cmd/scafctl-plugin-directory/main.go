// Package main is the entry point for the scafctl-plugin-directory plugin.
package main

import (
	"github.com/oakwood-commons/scafctl-plugin-directory/internal/directory"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

func main() {
	sdkplugin.Serve(&directory.Plugin{})
}
