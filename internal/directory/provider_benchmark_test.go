package directory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	sdkprovider "github.com/oakwood-commons/scafctl-plugin-sdk/provider"
)

func BenchmarkExecuteProvider_List(b *testing.B) {
	p := NewPlugin()

	tmpDir := b.TempDir()
	for i := range 20 {
		name := filepath.Join(tmpDir, fmt.Sprintf("file-%02d.txt", i))
		if err := os.WriteFile(name, []byte("content"), 0o600); err != nil {
			b.Fatal(err)
		}
	}

	ctx := sdkprovider.WithWorkingDirectory(context.Background(), tmpDir)
	inputs := map[string]any{
		"operation": "list",
		"path":      tmpDir,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = p.ExecuteProvider(ctx, "directory", inputs)
	}
}

func BenchmarkExecuteProvider_DryRun(b *testing.B) {
	p := NewPlugin()

	ctx := sdkprovider.WithDryRun(context.Background(), true)
	ctx = sdkprovider.WithWorkingDirectory(ctx, b.TempDir())
	inputs := map[string]any{
		"operation": "mkdir",
		"path":      "/tmp/bench-dir",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = p.ExecuteProvider(ctx, "directory", inputs)
	}
}
