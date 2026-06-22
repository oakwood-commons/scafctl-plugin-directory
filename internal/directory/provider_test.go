package directory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	sdkprovider "github.com/oakwood-commons/scafctl-plugin-sdk/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetProviders(t *testing.T) {
	p := NewPlugin()
	names, err := p.GetProviders(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"directory"}, names)
}

func TestGetProviderDescriptor(t *testing.T) {
	p := NewPlugin()
	desc, err := p.GetProviderDescriptor(context.Background(), "directory")
	require.NoError(t, err)
	require.NotNil(t, desc)

	assert.Equal(t, "directory", desc.Name)
	assert.Equal(t, "Directory Provider", desc.DisplayName)
	assert.Equal(t, "v1", desc.APIVersion)
	assert.Equal(t, "filesystem", desc.Category)
	assert.Contains(t, desc.Capabilities, sdkprovider.CapabilityFrom)
	assert.Contains(t, desc.Capabilities, sdkprovider.CapabilityAction)
	assert.NotNil(t, desc.Schema.Properties)
	assert.Contains(t, desc.Schema.Properties, "operation")
	assert.Contains(t, desc.Schema.Properties, "path")
	assert.Contains(t, desc.Schema.Properties, "recursive")
	assert.Contains(t, desc.Schema.Properties, "maxDepth")
	assert.Contains(t, desc.Schema.Properties, "includeContent")
	assert.Contains(t, desc.Schema.Properties, "filterGlob")
	assert.Contains(t, desc.Schema.Properties, "filterRegex")
	assert.Contains(t, desc.Schema.Properties, "excludeHidden")
	assert.Contains(t, desc.Schema.Properties, "filesOnly")
	assert.Contains(t, desc.Schema.Properties, "checksum")
	assert.Contains(t, desc.Schema.Properties, "relativeTo")
	assert.Equal(t, []any{"auto", "solution", "cwd"}, desc.Schema.Properties["relativeTo"].Enum)
	assert.NotNil(t, desc.OutputSchemas[sdkprovider.CapabilityFrom])
	assert.NotNil(t, desc.OutputSchemas[sdkprovider.CapabilityAction])
	assert.NotEmpty(t, desc.Examples)
	assert.NotEmpty(t, desc.Tags)
}

func TestGetProviderDescriptor_Unknown(t *testing.T) {
	p := NewPlugin()
	_, err := p.GetProviderDescriptor(context.Background(), "nope")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestExecuteProvider_InvalidInput(t *testing.T) {
	p := NewPlugin()
	ctx := context.Background()

	t.Run("missing operation", func(t *testing.T) {
		_, err := p.ExecuteProvider(ctx, "directory", map[string]any{"path": "."})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "operation is required")
	})

	t.Run("missing path", func(t *testing.T) {
		_, err := p.ExecuteProvider(ctx, "directory", map[string]any{"operation": "list"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path is required")
	})

	t.Run("unsupported operation", func(t *testing.T) {
		_, err := p.ExecuteProvider(ctx, "directory", map[string]any{"operation": "invalid", "path": "."})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported operation")
	})

	t.Run("unknown provider", func(t *testing.T) {
		_, err := p.ExecuteProvider(ctx, "nope", map[string]any{"operation": "list", "path": "."})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown provider")
	})
}

// =============================================================================
// List operation tests
// =============================================================================

func TestList_FlatDirectory(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "file1.txt"), []byte("hello"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file2.go"), []byte("package main"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "subdir"), 0o750))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "list",
		"path":      dir,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	data := result.Data.(map[string]any)

	assert.Equal(t, 3, data["totalCount"])
	assert.Equal(t, 1, data["dirCount"])
	assert.Equal(t, 2, data["fileCount"])
	assert.Equal(t, dir, data["basePath"])

	entries := data["entries"].([]map[string]any)
	assert.Len(t, entries, 3)
}

func TestList_Recursive(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "a", "b"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.txt"), []byte("root"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a", "mid.txt"), []byte("mid"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a", "b", "deep.txt"), []byte("deep"), 0o600))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "list",
		"path":      dir,
		"recursive": true,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.Equal(t, 5, data["totalCount"])
	assert.Equal(t, 2, data["dirCount"])
	assert.Equal(t, 3, data["fileCount"])
}

func TestList_MaxDepth(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "a", "b", "c"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a", "b", "c", "deep.txt"), []byte("deep"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a", "shallow.txt"), []byte("shallow"), 0o600))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "list",
		"path":      dir,
		"recursive": true,
		"maxDepth":  1,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	entries := data["entries"].([]map[string]any)

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e["path"].(string))
	}
	assert.Contains(t, names, "a")
	assert.Contains(t, names, "a/shallow.txt")
	assert.Contains(t, names, "a/b")
	assert.NotContains(t, names, "a/b/c")
}

func TestList_FilterGlob(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.go"), []byte("package main"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "readme.md"), []byte("# Readme"), 0o600))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":  "list",
		"path":       dir,
		"filterGlob": "*.go",
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.Equal(t, 2, data["fileCount"])
}

func TestList_FilterGlob_Recursive(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.go"), []byte("package main"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.txt"), []byte("text"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "nested.go"), []byte("package sub"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "nested.txt"), []byte("text"), 0o600))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":  "list",
		"path":       dir,
		"recursive":  true,
		"filterGlob": "*.go",
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.Equal(t, 2, data["fileCount"])
}

func TestList_FilterRegex(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "test_main.py"), []byte("pass"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test_utils.py"), []byte("pass"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.py"), []byte("pass"), 0o600))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":   "list",
		"path":        dir,
		"filterRegex": "^test_.*\\.py$",
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.Equal(t, 2, data["fileCount"])
}

func TestList_MutuallyExclusiveFilters(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":   "list",
		"path":        dir,
		"filterGlob":  "*.go",
		"filterRegex": "test_.*",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestList_InvalidRegex(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":   "list",
		"path":        dir,
		"filterRegex": "[invalid",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid filterRegex")
}

func TestList_ExcludeHidden(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, ".hidden"), []byte("secret"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "visible.txt"), []byte("public"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".hiddendir"), 0o750))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":     "list",
		"path":          dir,
		"excludeHidden": true,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.Equal(t, 1, data["totalCount"])
}

func TestList_FilesOnly(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "file1.txt"), []byte("hello"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "subdir"), 0o750))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "list",
		"path":      dir,
		"filesOnly": true,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.Equal(t, 1, data["totalCount"])
	assert.Equal(t, 0, data["dirCount"])
	assert.Equal(t, 1, data["fileCount"])
}

func TestList_FilesOnly_Recursive(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "a", "b"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.txt"), []byte("root"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a", "mid.txt"), []byte("mid"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a", "b", "deep.txt"), []byte("deep"), 0o600))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "list",
		"path":      dir,
		"recursive": true,
		"filesOnly": true,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.Equal(t, 3, data["totalCount"])
	assert.Equal(t, 0, data["dirCount"])
	assert.Equal(t, 3, data["fileCount"])
}

func TestList_IncludeContent(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	content := "Hello, World!"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte(content), 0o600))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":      "list",
		"path":           dir,
		"includeContent": true,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	entries := data["entries"].([]map[string]any)
	require.Len(t, entries, 1)

	assert.Equal(t, content, entries[0]["content"])
	assert.Equal(t, "text", entries[0]["contentEncoding"])
}

func TestList_IncludeContent_BinaryFile(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	binaryData := []byte{0x89, 0x50, 0x4E, 0x47, 0x00, 0x01, 0x02, 0x03}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "image.png"), binaryData, 0o600))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":      "list",
		"path":           dir,
		"includeContent": true,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	entries := data["entries"].([]map[string]any)
	require.Len(t, entries, 1)

	assert.Equal(t, "base64", entries[0]["contentEncoding"])
	decoded, err := base64.StdEncoding.DecodeString(entries[0]["content"].(string))
	require.NoError(t, err)
	assert.Equal(t, binaryData, decoded)
}

func TestList_IncludeContent_ExceedsMaxFileSize(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	largeContent := make([]byte, 100)
	for i := range largeContent {
		largeContent[i] = 'A'
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "large.txt"), largeContent, 0o600))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":      "list",
		"path":           dir,
		"includeContent": true,
		"maxFileSize":    50,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	entries := data["entries"].([]map[string]any)
	require.Len(t, entries, 1)

	_, hasContent := entries[0]["content"]
	assert.False(t, hasContent)
	assert.NotEmpty(t, result.Warnings)
	assert.Contains(t, result.Warnings[0], "exceeds maxFileSize")
}

func TestList_Checksum(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0o600))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":      "list",
		"path":           dir,
		"includeContent": true,
		"checksum":       "sha256",
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	entries := data["entries"].([]map[string]any)
	require.Len(t, entries, 1)

	assert.NotEmpty(t, entries[0]["checksum"])
	assert.Equal(t, "sha256", entries[0]["checksumAlgorithm"])
	assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", entries[0]["checksum"])
}

func TestList_InvalidChecksum(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":      "list",
		"path":           dir,
		"includeContent": true,
		"checksum":       "md5",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported checksum algorithm")
}

func TestList_SkipsSymlinks(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	targetFile := filepath.Join(dir, "target.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("target"), 0o600))
	require.NoError(t, os.Symlink(targetFile, filepath.Join(dir, "link.txt")))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "list",
		"path":      dir,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.Equal(t, 1, data["fileCount"])
}

func TestList_NonexistentDir(t *testing.T) {
	p := NewPlugin()

	_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "list",
		"path":      "/nonexistent/directory",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

func TestList_PathIsFile(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	filePath := filepath.Join(dir, "file.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("content"), 0o600))

	_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "list",
		"path":      filePath,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

func TestList_EmptyDirectory(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "list",
		"path":      dir,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.Equal(t, 0, data["totalCount"])
}

func TestList_FileMetadata(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.go"), []byte("package main"), 0o600))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "list",
		"path":      dir,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	entries := data["entries"].([]map[string]any)
	require.Len(t, entries, 1)

	e := entries[0]
	assert.Equal(t, "test.go", e["name"])
	assert.Equal(t, ".go", e["extension"])
	assert.Equal(t, "file", e["type"])
	assert.False(t, e["isDir"].(bool))
	assert.NotEmpty(t, e["mode"])
	assert.NotEmpty(t, e["modTime"])
	assert.Equal(t, int64(12), e["size"])
}

func TestList_InvalidMaxDepth(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	t.Run("too low", func(t *testing.T) {
		_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
			"operation": "list",
			"path":      dir,
			"maxDepth":  0,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maxDepth must be between")
	})

	t.Run("too high", func(t *testing.T) {
		_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
			"operation": "list",
			"path":      dir,
			"maxDepth":  100,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maxDepth must be between")
	})
}

func TestList_TotalSize(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaaa"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("bbbbbb"), 0o600))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "list",
		"path":      dir,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.Equal(t, int64(10), data["totalSize"])
}

// =============================================================================
// Mkdir operation tests
// =============================================================================

func TestMkdir_Simple(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()
	newDir := filepath.Join(dir, "newdir")

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "mkdir",
		"path":      newDir,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.True(t, data["success"].(bool))
	assert.Equal(t, "mkdir", data["operation"])

	info, err := os.Stat(newDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestMkdir_WithCreateDirs(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()
	newDir := filepath.Join(dir, "a", "b", "c")

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":  "mkdir",
		"path":       newDir,
		"createDirs": true,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.True(t, data["success"].(bool))

	info, err := os.Stat(newDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestMkdir_WithoutCreateDirs_NestedFails(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()
	newDir := filepath.Join(dir, "a", "b", "c")

	_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "mkdir",
		"path":      newDir,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create directory")
}

func TestMkdir_AlreadyExists(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()
	existingDir := filepath.Join(dir, "existing")
	require.NoError(t, os.Mkdir(existingDir, 0o750))

	_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "mkdir",
		"path":      existingDir,
	})
	require.Error(t, err)

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":  "mkdir",
		"path":       existingDir,
		"createDirs": true,
	})
	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.True(t, data["success"].(bool))
}

// =============================================================================
// Rmdir operation tests
// =============================================================================

func TestRmdir_EmptyDir(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "removeme")
	require.NoError(t, os.Mkdir(targetDir, 0o750))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "rmdir",
		"path":      targetDir,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.True(t, data["success"].(bool))
	assert.Equal(t, "rmdir", data["operation"])

	_, err = os.Stat(targetDir)
	assert.True(t, os.IsNotExist(err))
}

func TestRmdir_NonEmptyWithoutForce(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "notempty")
	require.NoError(t, os.Mkdir(targetDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "file.txt"), []byte("content"), 0o600))

	_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "rmdir",
		"path":      targetDir,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove directory")
}

func TestRmdir_NonEmptyWithForce(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "forcedelete")
	require.NoError(t, os.MkdirAll(filepath.Join(targetDir, "sub"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "file.txt"), []byte("content"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "sub", "nested.txt"), []byte("nested"), 0o600))

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "rmdir",
		"path":      targetDir,
		"force":     true,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.True(t, data["success"].(bool))

	_, err = os.Stat(targetDir)
	assert.True(t, os.IsNotExist(err))
}

func TestRmdir_NonexistentDir(t *testing.T) {
	p := NewPlugin()

	_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "rmdir",
		"path":      "/nonexistent/directory/path",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

func TestRmdir_PathIsFile(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()
	filePath := filepath.Join(dir, "file.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("content"), 0o600))

	_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "rmdir",
		"path":      filePath,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

// =============================================================================
// Copy operation tests
// =============================================================================

func TestCopy_Success(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	srcDir := filepath.Join(dir, "source")
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "sub"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "file.txt"), []byte("root content"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "sub", "nested.txt"), []byte("nested"), 0o600))

	dstDir := filepath.Join(dir, "destination")

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":   "copy",
		"path":        srcDir,
		"destination": dstDir,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.True(t, data["success"].(bool))
	assert.Equal(t, "copy", data["operation"])

	content, err := os.ReadFile(filepath.Join(dstDir, "file.txt")) //nolint:gosec // dstDir is a temp directory
	require.NoError(t, err)
	assert.Equal(t, "root content", string(content))

	content, err = os.ReadFile(filepath.Join(dstDir, "sub", "nested.txt")) //nolint:gosec // dstDir is a temp directory
	require.NoError(t, err)
	assert.Equal(t, "nested", string(content))
}

func TestCopy_RelativeTo_Solution_ResolvesDestination(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	srcDir := filepath.Join(dir, "source")
	require.NoError(t, os.MkdirAll(srcDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "file.txt"), []byte("content"), 0o600))

	// With relativeTo: solution, a relative destination anchors to the working
	// directory (which the host sets to the solution directory).
	ctx := sdkprovider.WithWorkingDirectory(context.Background(), dir)
	result, err := p.ExecuteProvider(ctx, "directory", map[string]any{
		"operation":   "copy",
		"path":        srcDir,
		"destination": "destination",
		"relativeTo":  "solution",
	})
	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.Equal(t, filepath.Join(dir, "destination"), data["destination"])

	content, err := os.ReadFile(filepath.Join(dir, "destination", "file.txt")) //nolint:gosec // dir is a temp directory
	require.NoError(t, err)
	assert.Equal(t, "content", string(content))
}

func TestCopy_MissingDestination(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "copy",
		"path":      dir,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "destination is required")
}

func TestCopy_SourceNotExists(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":   "copy",
		"path":        "/nonexistent/source",
		"destination": filepath.Join(dir, "dest"),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

func TestCopy_SkipsSymlinksInSource(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	srcDir := filepath.Join(dir, "source")
	require.NoError(t, os.MkdirAll(srcDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "real.txt"), []byte("real"), 0o600))

	secretFile := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte("secret data"), 0o600))
	require.NoError(t, os.Symlink(secretFile, filepath.Join(srcDir, "link.txt")))

	dstDir := filepath.Join(dir, "destination")
	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":   "copy",
		"path":        srcDir,
		"destination": dstDir,
	})
	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.True(t, data["success"].(bool))

	content, err := os.ReadFile(filepath.Join(dstDir, "real.txt")) //nolint:gosec // dstDir is a temp directory
	require.NoError(t, err)
	assert.Equal(t, "real", string(content))

	_, err = os.Lstat(filepath.Join(dstDir, "link.txt"))
	assert.True(t, os.IsNotExist(err), "symlink should not have been copied")
}

func TestCopyFile_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()

	realFile := filepath.Join(dir, "real.txt")
	require.NoError(t, os.WriteFile(realFile, []byte("content"), 0o600))

	symlinkFile := filepath.Join(dir, "link.txt")
	require.NoError(t, os.Symlink(realFile, symlinkFile))

	dst := filepath.Join(dir, "output.txt")
	err := copyFile(symlinkFile, dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a regular file")
}

// =============================================================================
// Move operation tests
// =============================================================================

func TestMove_Success(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	srcDir := filepath.Join(dir, "source")
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "sub"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "file.txt"), []byte("root content"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "sub", "nested.txt"), []byte("nested"), 0o600))

	dstDir := filepath.Join(dir, "destination")

	result, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":   "move",
		"path":        srcDir,
		"destination": dstDir,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.True(t, data["success"].(bool))
	assert.Equal(t, "move", data["operation"])

	content, err := os.ReadFile(filepath.Join(dstDir, "file.txt")) //nolint:gosec // dstDir is a temp directory
	require.NoError(t, err)
	assert.Equal(t, "root content", string(content))

	_, err = os.Stat(srcDir)
	assert.True(t, os.IsNotExist(err), "source should be removed after move")
}

func TestMove_MissingDestination(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation": "move",
		"path":      dir,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "destination is required")
}

func TestMove_SourceNotExists(t *testing.T) {
	p := NewPlugin()

	_, err := p.ExecuteProvider(context.Background(), "directory", map[string]any{
		"operation":   "move",
		"path":        "/nonexistent/dir",
		"destination": "/tmp/dest",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source directory does not exist")
}

// =============================================================================
// Dry-run tests
// =============================================================================

func TestDryRun_List(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file.txt"), []byte("content"), 0o600))

	ctx := sdkprovider.WithDryRun(context.Background(), true)
	result, err := p.ExecuteProvider(ctx, "directory", map[string]any{
		"operation": "list",
		"path":      dir,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.Equal(t, 1, data["fileCount"])
}

func TestDryRun_Mkdir(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()
	newDir := filepath.Join(dir, "newdir")

	ctx := sdkprovider.WithDryRun(context.Background(), true)
	result, err := p.ExecuteProvider(ctx, "directory", map[string]any{
		"operation": "mkdir",
		"path":      newDir,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.True(t, data["success"].(bool))
	assert.True(t, data["_dryRun"].(bool))
	assert.Contains(t, data["_message"].(string), "Would create directory")

	_, err = os.Stat(newDir)
	assert.True(t, os.IsNotExist(err))
}

func TestDryRun_Rmdir(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "removeme")
	require.NoError(t, os.Mkdir(targetDir, 0o750))

	ctx := sdkprovider.WithDryRun(context.Background(), true)
	result, err := p.ExecuteProvider(ctx, "directory", map[string]any{
		"operation": "rmdir",
		"path":      targetDir,
		"force":     true,
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.True(t, data["_dryRun"].(bool))
	assert.Contains(t, data["_message"].(string), "force-remove")

	_, err = os.Stat(targetDir)
	assert.NoError(t, err)
}

func TestDryRun_Copy(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	ctx := sdkprovider.WithDryRun(context.Background(), true)
	result, err := p.ExecuteProvider(ctx, "directory", map[string]any{
		"operation":   "copy",
		"path":        dir,
		"destination": filepath.Join(dir, "dest"),
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.True(t, data["_dryRun"].(bool))
	assert.Contains(t, data["_message"].(string), "Would copy")
}

func TestDryRun_Copy_TraversalError(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	ctx := context.Background()
	ctx = sdkprovider.WithDryRun(ctx, true)
	ctx = sdkprovider.WithExecutionMode(ctx, sdkprovider.CapabilityAction)
	ctx = sdkprovider.WithOutputDirectory(ctx, "/tmp/output")

	_, err := p.ExecuteProvider(ctx, "directory", map[string]any{
		"operation":   "copy",
		"path":        dir,
		"destination": "../../../etc/escape",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolving copy destination")
}

func TestDryRun_Copy_MissingDestination(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	ctx := sdkprovider.WithDryRun(context.Background(), true)

	_, err := p.ExecuteProvider(ctx, "directory", map[string]any{
		"operation": "copy",
		"path":      dir,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "destination is required")
}

func TestDryRun_Move(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	ctx := sdkprovider.WithDryRun(context.Background(), true)
	result, err := p.ExecuteProvider(ctx, "directory", map[string]any{
		"operation":   "move",
		"path":        dir,
		"destination": filepath.Join(dir, "dest"),
	})

	require.NoError(t, err)
	data := result.Data.(map[string]any)
	assert.True(t, data["_dryRun"].(bool))
	assert.Contains(t, data["_message"].(string), "Would move")
}

func TestDryRun_Move_MissingDestination(t *testing.T) {
	p := NewPlugin()
	dir := t.TempDir()

	ctx := sdkprovider.WithDryRun(context.Background(), true)

	_, err := p.ExecuteProvider(ctx, "directory", map[string]any{
		"operation": "move",
		"path":      dir,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "destination is required")
}

// =============================================================================
// DescribeWhatIf tests
// =============================================================================

func TestDescribeWhatIf(t *testing.T) {
	p := NewPlugin()

	tests := []struct {
		name     string
		inputs   map[string]any
		contains string
	}{
		{"mkdir", map[string]any{"operation": "mkdir", "path": "/tmp/mydir"}, "/tmp/mydir"},
		{"rmdir", map[string]any{"operation": "rmdir", "path": "/tmp/mydir"}, "/tmp/mydir"},
		{"copy", map[string]any{"operation": "copy", "path": "/tmp/src", "destination": "/tmp/dst"}, "/tmp/src"},
		{"move", map[string]any{"operation": "move", "path": "/tmp/src", "destination": "/tmp/dst"}, "/tmp/src"},
		{"list", map[string]any{"operation": "list", "path": "/tmp"}, "/tmp"},
		{"unknown", map[string]any{"operation": "unknown", "path": "/tmp/x"}, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := p.DescribeWhatIf(context.Background(), "directory", tt.inputs)
			require.NoError(t, err)
			assert.Contains(t, msg, tt.contains)
		})
	}
}

func TestDescribeWhatIf_UnknownProvider(t *testing.T) {
	p := NewPlugin()
	_, err := p.DescribeWhatIf(context.Background(), "nope", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

// =============================================================================
// Helper function tests
// =============================================================================

func TestIsBinary(t *testing.T) {
	assert.False(t, isBinary([]byte("Hello, World!\nThis is text.")))
	assert.True(t, isBinary([]byte{0x89, 0x50, 0x4E, 0x47, 0x00, 0x01}))
	assert.False(t, isBinary([]byte{}))
}

func TestMatchesFilter(t *testing.T) {
	t.Run("no filter matches all", func(t *testing.T) {
		assert.True(t, matchesFilter("anything.txt", &listOptions{}))
	})

	t.Run("glob matches", func(t *testing.T) {
		opts := &listOptions{filterGlob: "*.go"}
		assert.True(t, matchesFilter("main.go", opts))
		assert.False(t, matchesFilter("readme.md", opts))
	})

	t.Run("regex matches", func(t *testing.T) {
		opts := &listOptions{filterRegex: regexp.MustCompile(`^test_.*\.py$`)}
		assert.True(t, matchesFilter("test_main.py", opts))
		assert.False(t, matchesFilter("main.py", opts))
	})
}

func TestToInt(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		v, err := toInt(42)
		require.NoError(t, err)
		assert.Equal(t, 42, v)
	})

	t.Run("int64", func(t *testing.T) {
		v, err := toInt(int64(42))
		require.NoError(t, err)
		assert.Equal(t, 42, v)
	})

	t.Run("float64", func(t *testing.T) {
		v, err := toInt(42.0)
		require.NoError(t, err)
		assert.Equal(t, 42, v)
	})

	t.Run("string fails", func(t *testing.T) {
		_, err := toInt("42")
		require.Error(t, err)
	})

	t.Run("json.Number", func(t *testing.T) {
		v, err := toInt(json.Number("99"))
		require.NoError(t, err)
		assert.Equal(t, 99, v)
	})

	t.Run("json.Number invalid", func(t *testing.T) {
		_, err := toInt(json.Number("not-a-number"))
		require.Error(t, err)
	})
}

func TestToInt64(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		v, err := toInt64(42)
		require.NoError(t, err)
		assert.Equal(t, int64(42), v)
	})

	t.Run("json.Number", func(t *testing.T) {
		v, err := toInt64(json.Number("77"))
		require.NoError(t, err)
		assert.Equal(t, int64(77), v)
	})

	t.Run("string fails", func(t *testing.T) {
		_, err := toInt64("42")
		require.Error(t, err)
	})
}

// =============================================================================
// Plugin interface tests
// =============================================================================

func TestConfigureProvider(t *testing.T) {
	p := NewPlugin()
	err := p.ConfigureProvider(context.Background(), "directory", sdkplugin.ProviderConfig{})
	assert.NoError(t, err)
}

func TestExtractDependencies(t *testing.T) {
	p := NewPlugin()
	deps, err := p.ExtractDependencies(context.Background(), "directory", nil)
	assert.NoError(t, err)
	assert.Nil(t, deps)
}

func TestStopProvider(t *testing.T) {
	p := NewPlugin()
	err := p.StopProvider(context.Background(), "directory")
	assert.NoError(t, err)
}

func TestExecuteProviderStream(t *testing.T) {
	p := NewPlugin()
	err := p.ExecuteProviderStream(context.Background(), "directory", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "streaming")
}

// =============================================================================
// Path resolution tests
// =============================================================================

func TestResolvePath_Absolute(t *testing.T) {
	ctx := context.Background()
	result, err := resolvePath(ctx, "/absolute/path")
	require.NoError(t, err)
	assert.Equal(t, "/absolute/path", result)
}

func TestResolvePath_WithWorkingDirectory(t *testing.T) {
	ctx := sdkprovider.WithWorkingDirectory(context.Background(), "/work")
	result, err := resolvePath(ctx, "relative/path")
	require.NoError(t, err)
	assert.Equal(t, "/work/relative/path", result)
}

func TestResolvePath_OutputDirContainment(t *testing.T) {
	ctx := context.Background()
	ctx = sdkprovider.WithExecutionMode(ctx, sdkprovider.CapabilityAction)
	ctx = sdkprovider.WithOutputDirectory(ctx, "/tmp/output")

	_, err := resolvePath(ctx, "../../../etc/passwd")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolves outside output directory")
}

func TestResolvePathRel_Absolute(t *testing.T) {
	ctx := sdkprovider.WithWorkingDirectory(context.Background(), "/work")
	for _, relativeTo := range []string{"auto", "solution", "cwd", ""} {
		result, err := resolvePathRel(ctx, "/absolute/path", relativeTo)
		require.NoError(t, err)
		assert.Equal(t, "/absolute/path", result, "relativeTo=%q", relativeTo)
	}
}

func TestResolvePathRel_Solution_AnchorContextWorkingDirectory(t *testing.T) {
	ctx := sdkprovider.WithWorkingDirectory(context.Background(), "/work")
	result, err := resolvePathRel(ctx, "relative/path", "solution")
	require.NoError(t, err)
	assert.Equal(t, "/work/relative/path", result)
}

func TestResolvePathRel_Cwd_AnchorProcessWorkingDirectory(t *testing.T) {
	origDir, err := os.Getwd()
	require.NoError(t, err)

	tmpDir := t.TempDir()
	require.NoError(t, os.Chdir(tmpDir))
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	// Read back the resolved CWD to handle symlinks (e.g. /var → /private/var on macOS).
	resolvedCwd, err := os.Getwd()
	require.NoError(t, err)

	// No context working directory set — cwd must use the process CWD, not the context.
	ctx := context.Background()
	result, err := resolvePathRel(ctx, "relative/path", "cwd")
	require.NoError(t, err)
	assert.Equal(t, filepath.Clean(filepath.Join(resolvedCwd, "relative/path")), result)
}

func TestResolvePathRel_AutoDelegatesToResolvePath(t *testing.T) {
	ctx := context.Background()
	ctx = sdkprovider.WithExecutionMode(ctx, sdkprovider.CapabilityAction)
	ctx = sdkprovider.WithOutputDirectory(ctx, "/tmp/output")

	// In action mode with an output directory, auto anchors to the output dir.
	result, err := resolvePathRel(ctx, "sub/dir", "auto")
	require.NoError(t, err)
	assert.Equal(t, "/tmp/output/sub/dir", result)
}

func TestResolvePathRel_Solution_ActionMode_OutputDirContainment(t *testing.T) {
	ctx := context.Background()
	ctx = sdkprovider.WithExecutionMode(ctx, sdkprovider.CapabilityAction)
	ctx = sdkprovider.WithWorkingDirectory(ctx, "/tmp/output")
	ctx = sdkprovider.WithOutputDirectory(ctx, "/tmp/output")

	_, err := resolvePathRel(ctx, "../../../etc/passwd", "solution")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolves outside output directory")
}

func TestResolvePathRel_Cwd_ActionMode_OutputDirContainment(t *testing.T) {
	outputDir := t.TempDir()

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(outputDir))
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	ctx := context.Background()
	ctx = sdkprovider.WithExecutionMode(ctx, sdkprovider.CapabilityAction)
	ctx = sdkprovider.WithOutputDirectory(ctx, outputDir)

	_, err = resolvePathRel(ctx, "../../../etc/passwd", "cwd")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolves outside output directory")
}

func TestResolvePathRel_Unknown_ReturnsError(t *testing.T) {
	ctx := context.Background()
	_, err := resolvePathRel(ctx, "relative/path", "unknown-value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported relativeTo value")
}

func TestResolvePathRel_Unknown_AbsolutePath_ReturnsError(t *testing.T) {
	// An invalid relativeTo must be rejected even when path is absolute,
	// ensuring validation runs before the absolute-path fast-path.
	ctx := context.Background()
	_, err := resolvePathRel(ctx, "/absolute/path", "unknown-value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported relativeTo value")
}

func TestResolvePathRel_Solution_BypassesOutputDirAnchor(t *testing.T) {
	// solution anchors to the context working directory even in action mode,
	// rather than joining onto the output directory like auto does.
	ctx := context.Background()
	ctx = sdkprovider.WithExecutionMode(ctx, sdkprovider.CapabilityAction)
	ctx = sdkprovider.WithWorkingDirectory(ctx, "/work")

	result, err := resolvePathRel(ctx, "relative/path", "solution")
	require.NoError(t, err)
	assert.Equal(t, "/work/relative/path", result)
}
