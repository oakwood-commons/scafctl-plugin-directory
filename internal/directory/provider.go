// Package directory implements a directory operations provider plugin for scafctl.
package directory

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"mime"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/go-logr/logr"
	"github.com/google/jsonschema-go/jsonschema"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	sdkprovider "github.com/oakwood-commons/scafctl-plugin-sdk/provider"
	"github.com/oakwood-commons/scafctl-plugin-sdk/provider/schemahelper"
)

// ProviderName is the name of this provider.
const ProviderName = "directory"

const (
	// DefaultMaxDepth is the default recursion depth for directory listing.
	DefaultMaxDepth = 10
	// MaxAllowedDepth is the absolute maximum recursion depth.
	MaxAllowedDepth = 50
	// DefaultMaxFileSize is the default max file size for content reading (1 MB).
	DefaultMaxFileSize = 1 << 20
	// binaryDetectSize is the number of bytes to sample for binary detection.
	binaryDetectSize = 8192
)

// Plugin implements the ProviderPlugin interface for directory operations.
type Plugin struct{}

// NewPlugin creates a new directory plugin instance.
func NewPlugin() *Plugin {
	return &Plugin{}
}

var version = func() *semver.Version {
	v, _ := semver.NewVersion("1.0.0")
	return v
}()

func buildDescriptor() *sdkprovider.Descriptor {
	return &sdkprovider.Descriptor{
		Name:        ProviderName,
		DisplayName: "Directory Provider",
		Description: "Provider for directory operations: listing contents with filtering, creating, removing, and copying directories",
		APIVersion:  "v1",
		Version:     version,
		Category:    "filesystem",
		Tags:        []string{"directory", "filesystem", "listing", "glob", "scan"},
		Capabilities: []sdkprovider.Capability{
			sdkprovider.CapabilityFrom,
			sdkprovider.CapabilityAction,
		},
		Schema: schemahelper.ObjectSchema([]string{"operation", "path"}, map[string]*jsonschema.Schema{
			"operation": schemahelper.StringProp("Operation to perform",
				schemahelper.WithExample("list"),
				schemahelper.WithEnum("list", "mkdir", "rmdir", "copy", "move")),
			"path": schemahelper.StringProp("Target directory path (absolute or relative)",
				schemahelper.WithExample("./src"),
				schemahelper.WithMaxLength(4096)),
			"recursive": schemahelper.BoolProp("Enable recursive directory traversal",
				schemahelper.WithDefault(false)),
			"maxDepth": schemahelper.IntProp("Maximum recursion depth (1-50)",
				schemahelper.WithDefault(DefaultMaxDepth),
				schemahelper.WithMinimum(1),
				schemahelper.WithMaximum(MaxAllowedDepth)),
			"includeContent": schemahelper.BoolProp("Read and include file contents in output",
				schemahelper.WithDefault(false)),
			"maxFileSize": schemahelper.IntProp("Maximum file size in bytes for content reading; files exceeding this are skipped",
				schemahelper.WithDefault(DefaultMaxFileSize),
				schemahelper.WithMinimum(0)),
			"filterGlob": schemahelper.StringProp("Glob pattern to filter entries (e.g., '*.go', '**/*.yaml'). Mutually exclusive with filterRegex",
				schemahelper.WithExample("*.go"),
				schemahelper.WithMaxLength(500)),
			"filterRegex": schemahelper.StringProp("Regular expression to filter entry names. Mutually exclusive with filterGlob",
				schemahelper.WithExample("^test_.*\\.py$"),
				schemahelper.WithMaxLength(500)),
			"excludeHidden": schemahelper.BoolProp("Exclude hidden files and directories (names starting with '.')",
				schemahelper.WithDefault(false)),
			"checksum": schemahelper.StringProp("Compute checksum for files (requires includeContent). Supported: sha256, sha512",
				schemahelper.WithEnum("sha256", "sha512")),
			"createDirs": schemahelper.BoolProp("Create parent directories for mkdir (like mkdir -p)",
				schemahelper.WithDefault(false)),
			"destination": schemahelper.StringProp("Destination path for copy operation",
				schemahelper.WithMaxLength(4096)),
			"filesOnly": schemahelper.BoolProp("Exclude directory entries from list output; only file entries are returned",
				schemahelper.WithDefault(false)),
			"force": schemahelper.BoolProp("Force removal of non-empty directories for rmdir",
				schemahelper.WithDefault(false)),
			"relativeTo": schemahelper.StringProp(
				"Base directory anchor for resolving relative path and destination inputs. "+
					"solution: resolve relative to the solution directory. During the resolver phase the "+
					"host sets the working directory to the solution directory, so this anchors near the "+
					"solution file regardless of where the CLI is invoked from. "+
					"cwd: resolve relative to the process working directory. "+
					"auto (default): uses the output directory as the anchor in action mode when set (with "+
					"containment validation); otherwise the working directory. "+
					"Note: solution and cwd anchors enforce output-directory containment when an output "+
					"directory is set. In action mode the solution anchor resolves against the working "+
					"directory, which equals the solution directory only during the resolver phase.",
				schemahelper.WithExample("solution"),
				schemahelper.WithDefault("auto"),
				schemahelper.WithEnum("auto", "solution", "cwd")),
		}),
		OutputSchemas: map[sdkprovider.Capability]*jsonschema.Schema{
			sdkprovider.CapabilityFrom: schemahelper.ObjectSchema(nil, map[string]*jsonschema.Schema{
				"entries": schemahelper.ArrayProp("List of directory entries",
					schemahelper.WithItems(schemahelper.ObjectProp("A directory entry",
						nil,
						map[string]*jsonschema.Schema{
							"path":              schemahelper.StringProp("Relative path from the listed directory"),
							"absolutePath":      schemahelper.StringProp("Absolute filesystem path"),
							"name":              schemahelper.StringProp("File or directory name"),
							"extension":         schemahelper.StringProp("File extension including dot (e.g., '.go')"),
							"size":              schemahelper.IntProp("Size in bytes"),
							"isDir":             schemahelper.BoolProp("Whether this entry is a directory"),
							"type":              schemahelper.StringProp("Entry type: file or dir"),
							"mode":              schemahelper.StringProp("File permission mode (e.g., '0644')"),
							"modTime":           schemahelper.StringProp("Last modification time in RFC3339 format"),
							"mimeType":          schemahelper.StringProp("MIME type based on file extension"),
							"content":           schemahelper.StringProp("File content (only when includeContent is true)"),
							"contentEncoding":   schemahelper.StringProp("Content encoding: text or base64"),
							"checksum":          schemahelper.StringProp("File checksum (only when checksum algorithm is specified)"),
							"checksumAlgorithm": schemahelper.StringProp("Checksum algorithm used"),
						},
					))),
				"totalCount": schemahelper.IntProp("Total number of entries"),
				"dirCount":   schemahelper.IntProp("Number of directories"),
				"fileCount":  schemahelper.IntProp("Number of files"),
				"totalSize":  schemahelper.IntProp("Total size of all files in bytes"),
				"basePath":   schemahelper.StringProp("Absolute path of the listed directory"),
			}),
			sdkprovider.CapabilityAction: schemahelper.ObjectSchema(nil, map[string]*jsonschema.Schema{
				"success":   schemahelper.BoolProp("Whether the operation succeeded"),
				"operation": schemahelper.StringProp("Operation that was performed"),
				"path":      schemahelper.StringProp("Absolute path of the target directory"),
			}),
		},
		Examples: []sdkprovider.Example{
			{
				Name:        "List directory contents",
				Description: "List files and directories in the current directory",
				YAML: `name: list-src
provider: directory
inputs:
  operation: list
  path: ./src`,
			},
			{
				Name:        "Recursive listing with glob filter",
				Description: "Recursively list all Go files in a directory",
				YAML: `name: find-go-files
provider: directory
inputs:
  operation: list
  path: ./pkg
  recursive: true
  filterGlob: "*.go"`,
			},
			{
				Name:        "List with file contents",
				Description: "List YAML files and include their contents",
				YAML: `name: read-configs
provider: directory
inputs:
  operation: list
  path: ./config
  recursive: true
  includeContent: true
  filterGlob: "*.yaml"
  maxFileSize: 524288`,
			},
			{
				Name:        "Create directory",
				Description: "Create a nested directory structure",
				YAML: `name: create-output-dir
provider: directory
inputs:
  operation: mkdir
  path: ./output/reports/2026
  createDirs: true`,
			},
			{
				Name:        "Remove directory",
				Description: "Force-remove a directory and all its contents",
				YAML: `name: cleanup-temp
provider: directory
inputs:
  operation: rmdir
  path: ./tmp/build-output
  force: true`,
			},
			{
				Name:        "Copy directory",
				Description: "Copy a directory tree to a new location",
				YAML: `name: backup-config
provider: directory
inputs:
  operation: copy
  path: ./config
  destination: ./config-backup`,
			},
			{
				Name:        "Move directory",
				Description: "Move (rename) a directory to a new path",
				YAML: `name: rename-output
provider: directory
inputs:
  operation: move
  path: ./output
  destination: ./dist`,
			},
		},
	}
}

// GetProviders returns the list of provider names this plugin offers.
func (p *Plugin) GetProviders(_ context.Context) ([]string, error) {
	return []string{ProviderName}, nil
}

// GetProviderDescriptor returns the descriptor for the named provider.
func (p *Plugin) GetProviderDescriptor(_ context.Context, providerName string) (*sdkprovider.Descriptor, error) {
	if providerName != ProviderName {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}
	return buildDescriptor(), nil
}

// ConfigureProvider configures the provider (no-op for directory).
func (p *Plugin) ConfigureProvider(_ context.Context, _ string, _ sdkplugin.ProviderConfig) error {
	return nil
}

// ExecuteProvider performs the directory operation.
func (p *Plugin) ExecuteProvider(ctx context.Context, providerName string, inputs map[string]any) (*sdkprovider.Output, error) {
	if providerName != ProviderName {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}

	lgr := logr.FromContextOrDiscard(ctx)

	operation, ok := inputs["operation"].(string)
	if !ok {
		return nil, fmt.Errorf("%s: operation is required and must be a string", ProviderName)
	}

	path, ok := inputs["path"].(string)
	if !ok {
		return nil, fmt.Errorf("%s: path is required and must be a string", ProviderName)
	}

	relativeTo, _ := inputs["relativeTo"].(string)

	absPath, err := resolvePathRel(ctx, path, relativeTo)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid path: %w", ProviderName, err)
	}

	lgr.V(1).Info("executing provider", "provider", ProviderName, "operation", operation, "path", path)

	if dryRun := sdkprovider.DryRunFromContext(ctx); dryRun {
		result, dryErr := p.executeDryRun(ctx, operation, absPath, inputs)
		if dryErr != nil {
			return nil, fmt.Errorf("%s: %w", ProviderName, dryErr)
		}
		lgr.V(1).Info("provider completed (dry-run)", "provider", ProviderName, "operation", operation)
		return result, nil
	}

	var result *sdkprovider.Output
	switch operation {
	case "list":
		result, err = p.executeList(absPath, inputs)
	case "mkdir":
		result, err = p.executeMkdir(absPath, inputs)
	case "rmdir":
		result, err = p.executeRmdir(absPath, inputs)
	case "copy":
		result, err = p.executeCopy(ctx, absPath, inputs)
	case "move":
		result, err = p.executeMove(ctx, absPath, inputs)
	default:
		return nil, fmt.Errorf("%s: unsupported operation: %s", ProviderName, operation)
	}

	if err != nil {
		return nil, fmt.Errorf("%s: %w", ProviderName, err)
	}

	lgr.V(1).Info("provider completed", "provider", ProviderName, "operation", operation)
	return result, nil
}

// ExecuteProviderStream is not supported by the directory provider.
func (p *Plugin) ExecuteProviderStream(_ context.Context, _ string, _ map[string]any, _ func(sdkplugin.StreamChunk)) error {
	return sdkplugin.ErrStreamingNotSupported
}

// DescribeWhatIf returns a human-readable description of what the operation would do.
func (p *Plugin) DescribeWhatIf(_ context.Context, providerName string, inputs map[string]any) (string, error) {
	if providerName != ProviderName {
		return "", fmt.Errorf("unknown provider: %s", providerName)
	}

	operation, _ := inputs["operation"].(string)
	path, _ := inputs["path"].(string)

	switch operation {
	case "mkdir":
		return fmt.Sprintf("Would create directory %s", path), nil
	case "rmdir":
		return fmt.Sprintf("Would remove directory %s", path), nil
	case "copy":
		dest, _ := inputs["destination"].(string)
		return fmt.Sprintf("Would copy directory %s to %s", path, dest), nil
	case "move":
		dest, _ := inputs["destination"].(string)
		return fmt.Sprintf("Would move directory %s to %s", path, dest), nil
	case "list":
		return fmt.Sprintf("Would list directory %s", path), nil
	default:
		return fmt.Sprintf("Would perform directory %s on %s", operation, path), nil
	}
}

// ExtractDependencies returns nil (directory has no external dependencies).
func (p *Plugin) ExtractDependencies(_ context.Context, _ string, _ map[string]any) ([]string, error) {
	return nil, nil
}

// StopProvider is a no-op for the directory provider.
func (p *Plugin) StopProvider(_ context.Context, _ string) error {
	return nil
}

// resolvePathRel resolves a filesystem path according to the relativeTo anchor,
// mirroring the builtin file provider's semantics within the plugin SDK's
// capabilities.
//
//   - "solution": anchor to the working directory from context (falling back to
//     filepath.Abs). The host sets the working directory to the solution
//     directory during the resolver phase, so this resolves near the solution
//     file. In action mode the working directory is the process working
//     directory, not the solution directory; the plugin SDK does not expose a
//     separate solution-directory anchor, so this is the closest available
//     behavior.
//   - "cwd": anchor to the process working directory (os.Getwd()).
//   - "auto" or "": delegate to resolvePath, which uses the output directory as
//     the anchor in action mode when set, otherwise the working directory.
//
// For "solution" and "cwd", when in action mode with an output directory set,
// the resolved path is validated to ensure it does not escape that directory,
// preserving the containment guarantee that resolvePath provides for "auto".
// An unsupported relativeTo value always returns an error, even when path is absolute.
func resolvePathRel(ctx context.Context, path, relativeTo string) (string, error) {
	switch relativeTo {
	case "solution", "cwd", "auto", "":
		// valid values — handled below
	default:
		return "", fmt.Errorf("unsupported relativeTo value %q: must be one of \"auto\", \"solution\", or \"cwd\"", relativeTo)
	}

	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}

	switch relativeTo {
	case "solution":
		resolved, err := absFromContext(ctx, path)
		if err != nil {
			return "", err
		}
		resolved = filepath.Clean(resolved)

		if mode, modeOK := sdkprovider.ExecutionModeFromContext(ctx); modeOK && mode == sdkprovider.CapabilityAction {
			if outputDir, dirOK := sdkprovider.OutputDirectoryFromContext(ctx); dirOK && outputDir != "" {
				if err := validatePathContainment(outputDir, resolved); err != nil {
					return "", fmt.Errorf("path %q resolves outside output directory %q: %w", path, outputDir, err)
				}
			}
		}
		return resolved, nil

	case "cwd":
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("getting process working directory: %w", err)
		}
		resolved := filepath.Clean(filepath.Join(cwd, path))

		if mode, modeOK := sdkprovider.ExecutionModeFromContext(ctx); modeOK && mode == sdkprovider.CapabilityAction {
			if outputDir, dirOK := sdkprovider.OutputDirectoryFromContext(ctx); dirOK && outputDir != "" {
				if err := validatePathContainment(outputDir, resolved); err != nil {
					return "", fmt.Errorf("path %q resolves outside output directory %q: %w", path, outputDir, err)
				}
			}
		}
		return resolved, nil

	default: // "auto" or ""
		return resolvePath(ctx, path)
	}
}

// resolvePath resolves a filesystem path based on the current execution context.
// For action mode with an output directory, paths are resolved within the output
// directory and validated against directory traversal. Otherwise, paths are resolved
// against the working directory from context or the process CWD.
func resolvePath(ctx context.Context, path string) (string, error) {
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}

	mode, modeOK := sdkprovider.ExecutionModeFromContext(ctx)
	if modeOK && mode == sdkprovider.CapabilityAction {
		if outputDir, dirOK := sdkprovider.OutputDirectoryFromContext(ctx); dirOK && outputDir != "" {
			resolved := filepath.Clean(filepath.Join(outputDir, path))
			if err := validatePathContainment(outputDir, resolved); err != nil {
				return "", fmt.Errorf("path %q resolves outside output directory %q: %w", path, outputDir, err)
			}
			return resolved, nil
		}
	}

	return absFromContext(ctx, path)
}

// absFromContext resolves a relative path to an absolute path using the context
// working directory, falling back to filepath.Abs (process CWD).
func absFromContext(ctx context.Context, path string) (string, error) {
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	if cwd, ok := sdkprovider.WorkingDirectoryFromContext(ctx); ok && cwd != "" {
		return filepath.Join(cwd, path), nil
	}
	return filepath.Abs(path)
}

// validatePathContainment verifies that resolved is inside or equal to baseDir.
func validatePathContainment(baseDir, resolved string) error {
	realBase, err := evalSymlinksExisting(baseDir)
	if err != nil {
		realBase = baseDir
	}

	realResolved, err := evalSymlinksExisting(resolved)
	if err != nil {
		return fmt.Errorf("evaluating symlinks: %w", err)
	}

	rel, err := filepath.Rel(realBase, realResolved)
	if err != nil {
		return fmt.Errorf("cannot compute relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("resolved path escapes base directory")
	}
	return nil
}

// evalSymlinksExisting resolves symlinks for the longest existing prefix of path.
func evalSymlinksExisting(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}

	parent := filepath.Dir(path)
	if parent == path {
		return path, nil
	}

	resolvedParent, err := evalSymlinksExisting(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, filepath.Base(path)), nil
}

// listOptions holds parsed options for the list operation.
type listOptions struct {
	recursive      bool
	maxDepth       int
	includeContent bool
	maxFileSize    int64
	filterGlob     string
	filterRegex    *regexp.Regexp
	excludeHidden  bool
	checksum       string
	filesOnly      bool
}

// entryInfo holds information about a single directory entry.
type entryInfo struct {
	Path              string `json:"path"`
	AbsolutePath      string `json:"absolutePath"`
	Name              string `json:"name"`
	Extension         string `json:"extension"`
	Size              int64  `json:"size"`
	IsDir             bool   `json:"isDir"`
	Type              string `json:"type"`
	Mode              string `json:"mode"`
	ModTime           string `json:"modTime"`
	MimeType          string `json:"mimeType,omitempty"`
	Content           string `json:"content,omitempty"`
	ContentEncoding   string `json:"contentEncoding,omitempty"`
	Checksum          string `json:"checksum,omitempty"`
	ChecksumAlgorithm string `json:"checksumAlgorithm,omitempty"`
}

// parseListOptions parses and validates list operation inputs.
func parseListOptions(inputs map[string]any) (*listOptions, error) {
	opts := &listOptions{
		maxDepth:    DefaultMaxDepth,
		maxFileSize: DefaultMaxFileSize,
	}

	if v, ok := inputs["recursive"].(bool); ok {
		opts.recursive = v
	}

	if v, ok := inputs["maxDepth"]; ok {
		depth, err := toInt(v)
		if err != nil {
			return nil, fmt.Errorf("maxDepth must be an integer: %w", err)
		}
		if depth < 1 || depth > MaxAllowedDepth {
			return nil, fmt.Errorf("maxDepth must be between 1 and %d, got %d", MaxAllowedDepth, depth)
		}
		opts.maxDepth = depth
	}

	if v, ok := inputs["includeContent"].(bool); ok {
		opts.includeContent = v
	}

	if v, ok := inputs["maxFileSize"]; ok {
		size, err := toInt64(v)
		if err != nil {
			return nil, fmt.Errorf("maxFileSize must be an integer: %w", err)
		}
		if size < 0 {
			return nil, fmt.Errorf("maxFileSize must be non-negative, got %d", size)
		}
		opts.maxFileSize = size
	}

	if v, ok := inputs["filterGlob"].(string); ok && v != "" {
		opts.filterGlob = v
	}

	if v, ok := inputs["filterRegex"].(string); ok && v != "" {
		if opts.filterGlob != "" {
			return nil, fmt.Errorf("filterGlob and filterRegex are mutually exclusive")
		}
		re, err := regexp.Compile(v)
		if err != nil {
			return nil, fmt.Errorf("invalid filterRegex: %w", err)
		}
		opts.filterRegex = re
	}

	if v, ok := inputs["excludeHidden"].(bool); ok {
		opts.excludeHidden = v
	}

	if v, ok := inputs["filesOnly"].(bool); ok {
		opts.filesOnly = v
	}

	if v, ok := inputs["checksum"].(string); ok && v != "" {
		switch v {
		case "sha256", "sha512":
			opts.checksum = v
		default:
			return nil, fmt.Errorf("unsupported checksum algorithm: %s (supported: sha256, sha512)", v)
		}
	}

	return opts, nil
}

// executeList performs the list operation.
func (p *Plugin) executeList(absPath string, inputs map[string]any) (*sdkprovider.Output, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("directory does not exist: %s", absPath)
		}
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", absPath)
	}

	opts, err := parseListOptions(inputs)
	if err != nil {
		return nil, err
	}

	var entries []map[string]any
	var warnings []string
	var dirCount, fileCount int
	var totalSize int64

	walkErr := p.walkDirectory(absPath, absPath, 0, opts, func(entry entryInfo) {
		m := entryToMap(entry)
		entries = append(entries, m)
		if entry.IsDir {
			dirCount++
		} else {
			fileCount++
			totalSize += entry.Size
		}
	}, &warnings)

	if walkErr != nil {
		return nil, walkErr
	}

	if entries == nil {
		entries = []map[string]any{}
	}

	output := &sdkprovider.Output{
		Data: map[string]any{
			"entries":    entries,
			"totalCount": dirCount + fileCount,
			"dirCount":   dirCount,
			"fileCount":  fileCount,
			"totalSize":  totalSize,
			"basePath":   absPath,
		},
	}

	if len(warnings) > 0 {
		output.Warnings = warnings
	}

	return output, nil
}

// walkDirectory recursively traverses a directory tree.
func (p *Plugin) walkDirectory(
	basePath, currentPath string,
	depth int,
	opts *listOptions,
	emit func(entryInfo),
	warnings *[]string,
) error {
	dirEntries, err := os.ReadDir(currentPath)
	if err != nil {
		return fmt.Errorf("failed to read directory %s: %w", currentPath, err)
	}

	for _, de := range dirEntries {
		name := de.Name()

		if opts.excludeHidden && strings.HasPrefix(name, ".") {
			continue
		}

		if de.Type()&fs.ModeSymlink != 0 {
			continue
		}

		entryPath := filepath.Join(currentPath, name)
		relPath, _ := filepath.Rel(basePath, entryPath)

		fi, err := de.Info()
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf("failed to stat %s: %v", relPath, err))
			continue
		}

		if fi.Mode()&fs.ModeSymlink != 0 {
			continue
		}

		isDir := fi.IsDir()

		if !matchesFilter(name, opts) {
			if isDir && opts.recursive && depth < opts.maxDepth {
				if walkErr := p.walkDirectory(basePath, entryPath, depth+1, opts, emit, warnings); walkErr != nil {
					*warnings = append(*warnings, fmt.Sprintf("error traversing %s: %v", relPath, walkErr))
				}
			}
			continue
		}

		entry := entryInfo{
			Path:         filepath.ToSlash(relPath),
			AbsolutePath: entryPath,
			Name:         name,
			Size:         fi.Size(),
			IsDir:        isDir,
			Mode:         fmt.Sprintf("%04o", fi.Mode().Perm()),
			ModTime:      fi.ModTime().UTC().Format(time.RFC3339),
		}

		if isDir {
			entry.Type = "dir"
		} else {
			entry.Extension = filepath.Ext(name)
			if entry.Extension != "" {
				entry.MimeType = mime.TypeByExtension(entry.Extension)
			}
			entry.Type = "file"

			if opts.includeContent && fi.Size() <= opts.maxFileSize {
				content, encoding, readErr := readFileContent(entryPath)
				if readErr != nil {
					*warnings = append(*warnings, fmt.Sprintf("failed to read %s: %v", relPath, readErr))
				} else {
					entry.Content = content
					entry.ContentEncoding = encoding
				}
			} else if opts.includeContent && fi.Size() > opts.maxFileSize {
				*warnings = append(*warnings, fmt.Sprintf("skipped content for %s: size %d exceeds maxFileSize %d", relPath, fi.Size(), opts.maxFileSize))
			}

			if opts.checksum != "" && opts.includeContent && entry.Content != "" {
				cs, csErr := computeChecksum(entryPath, opts.checksum)
				if csErr != nil {
					*warnings = append(*warnings, fmt.Sprintf("failed to compute checksum for %s: %v", relPath, csErr))
				} else {
					entry.Checksum = cs
					entry.ChecksumAlgorithm = opts.checksum
				}
			}
		}

		if !isDir || !opts.filesOnly {
			emit(entry)
		}

		if isDir && opts.recursive && depth < opts.maxDepth {
			if walkErr := p.walkDirectory(basePath, entryPath, depth+1, opts, emit, warnings); walkErr != nil {
				*warnings = append(*warnings, fmt.Sprintf("error traversing %s: %v", relPath, walkErr))
			}
		}
	}

	return nil
}

// matchesFilter checks if a filename matches the configured filter.
func matchesFilter(name string, opts *listOptions) bool {
	if opts.filterGlob != "" {
		matched, err := filepath.Match(opts.filterGlob, name)
		if err != nil {
			return false
		}
		return matched
	}

	if opts.filterRegex != nil {
		return opts.filterRegex.MatchString(name)
	}

	return true
}

// entryToMap converts an entryInfo struct to a map[string]any.
func entryToMap(e entryInfo) map[string]any {
	m := map[string]any{
		"path":         e.Path,
		"absolutePath": e.AbsolutePath,
		"name":         e.Name,
		"extension":    e.Extension,
		"size":         e.Size,
		"isDir":        e.IsDir,
		"type":         e.Type,
		"mode":         e.Mode,
		"modTime":      e.ModTime,
	}

	if e.MimeType != "" {
		m["mimeType"] = e.MimeType
	}
	if e.Content != "" {
		m["content"] = e.Content
		m["contentEncoding"] = e.ContentEncoding
	}
	if e.Checksum != "" {
		m["checksum"] = e.Checksum
		m["checksumAlgorithm"] = e.ChecksumAlgorithm
	}

	return m
}

// readFileContent reads a file and returns its content as a string plus encoding type.
func readFileContent(path string) (content, encoding string, err error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is validated by callers
	if err != nil {
		return "", "", err
	}

	if isBinary(data) {
		return base64.StdEncoding.EncodeToString(data), "base64", nil
	}

	return string(data), "text", nil
}

// isBinary detects whether data is binary by checking for null bytes.
func isBinary(data []byte) bool {
	sample := data
	if len(sample) > binaryDetectSize {
		sample = sample[:binaryDetectSize]
	}

	for _, b := range sample {
		if b == 0 {
			return true
		}
	}

	return false
}

// computeChecksum computes a hash of the file at path using the given algorithm.
func computeChecksum(path, algorithm string) (_ string, err error) {
	f, err := os.Open(path) //nolint:gosec // path is validated by callers
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	var h hash.Hash
	switch algorithm {
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// executeMkdir creates a directory.
func (p *Plugin) executeMkdir(absPath string, inputs map[string]any) (*sdkprovider.Output, error) {
	createDirs, _ := inputs["createDirs"].(bool)

	if createDirs {
		if err := os.MkdirAll(absPath, 0o750); err != nil {
			return nil, fmt.Errorf("failed to create directories: %w", err)
		}
	} else {
		if err := os.Mkdir(absPath, 0o750); err != nil {
			return nil, fmt.Errorf("failed to create directory: %w", err)
		}
	}

	return &sdkprovider.Output{
		Data: map[string]any{
			"success":   true,
			"operation": "mkdir",
			"path":      absPath,
		},
	}, nil
}

// executeRmdir removes a directory.
func (p *Plugin) executeRmdir(absPath string, inputs map[string]any) (*sdkprovider.Output, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("directory does not exist: %s", absPath)
		}
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", absPath)
	}

	force, _ := inputs["force"].(bool)

	if force {
		if err := os.RemoveAll(absPath); err != nil {
			return nil, fmt.Errorf("failed to remove directory: %w", err)
		}
	} else {
		if err := os.Remove(absPath); err != nil {
			return nil, fmt.Errorf("failed to remove directory (is it empty?): %w", err)
		}
	}

	return &sdkprovider.Output{
		Data: map[string]any{
			"success":   true,
			"operation": "rmdir",
			"path":      absPath,
		},
	}, nil
}

// executeCopy copies a directory tree to a destination.
func (p *Plugin) executeCopy(ctx context.Context, absPath string, inputs map[string]any) (*sdkprovider.Output, error) {
	destination, ok := inputs["destination"].(string)
	if !ok || destination == "" {
		return nil, fmt.Errorf("destination is required for copy operation")
	}

	relativeTo, _ := inputs["relativeTo"].(string)
	absDest, err := resolvePathRel(ctx, destination, relativeTo)
	if err != nil {
		return nil, fmt.Errorf("invalid destination path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("source directory does not exist: %s", absPath)
		}
		return nil, fmt.Errorf("failed to stat source: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("source is not a directory: %s", absPath)
	}

	if err := copyDir(absPath, absDest); err != nil {
		return nil, fmt.Errorf("failed to copy directory: %w", err)
	}

	return &sdkprovider.Output{
		Data: map[string]any{
			"success":     true,
			"operation":   "copy",
			"path":        absPath,
			"destination": absDest,
		},
	}, nil
}

// executeMove moves (renames) a directory to a new location.
func (p *Plugin) executeMove(ctx context.Context, absPath string, inputs map[string]any) (*sdkprovider.Output, error) {
	destination, ok := inputs["destination"].(string)
	if !ok || destination == "" {
		return nil, fmt.Errorf("destination is required for move operation")
	}

	relativeTo, _ := inputs["relativeTo"].(string)
	absDest, err := resolvePathRel(ctx, destination, relativeTo)
	if err != nil {
		return nil, fmt.Errorf("invalid destination path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("source directory does not exist: %s", absPath)
		}
		return nil, fmt.Errorf("failed to stat source: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("source is not a directory: %s", absPath)
	}

	if renameErr := os.Rename(absPath, absDest); renameErr != nil {
		if !errors.Is(renameErr, syscall.EXDEV) {
			return nil, fmt.Errorf("failed to rename directory: %w", renameErr)
		}
		if err := copyDir(absPath, absDest); err != nil {
			return nil, fmt.Errorf("failed to move directory (copy phase): %w", err)
		}
		if err := os.RemoveAll(absPath); err != nil {
			return nil, fmt.Errorf("failed to move directory (remove source phase): %w", err)
		}
	}

	return &sdkprovider.Output{
		Data: map[string]any{
			"success":     true,
			"operation":   "move",
			"path":        absPath,
			"destination": absDest,
		},
	}, nil
}

// copyDir recursively copies a directory tree from src to dst.
func copyDir(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dst, srcInfo.Mode().Perm()); err != nil {
		return fmt.Errorf("creating destination directory: %w", err)
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.Type()&fs.ModeSymlink != 0 {
			continue
		}

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// copyFile copies a single file from src to dst, preserving permissions.
// Guards against symlink TOCTOU attacks.
func copyFile(src, dst string) (err error) {
	lstatInfo, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !lstatInfo.Mode().IsRegular() {
		return fmt.Errorf("source is not a regular file: %s", src)
	}

	srcFile, err := os.Open(src) //nolint:gosec // src is validated against symlinks with the Lstat check above
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := srcFile.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	openedInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(lstatInfo, openedInfo) {
		return fmt.Errorf("source file changed between check and open (possible symlink attack): %s", src)
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, lstatInfo.Mode().Perm()) //nolint:gosec // dst is a resolved output path
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := dstFile.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	return nil
}

// executeDryRun handles dry-run mode for mutating operations.
func (p *Plugin) executeDryRun(ctx context.Context, operation, absPath string, inputs map[string]any) (*sdkprovider.Output, error) {
	switch operation {
	case "list":
		return p.executeList(absPath, inputs)

	case "mkdir":
		createDirs, _ := inputs["createDirs"].(bool)
		msg := fmt.Sprintf("Would create directory: %s", absPath)
		if createDirs {
			msg = fmt.Sprintf("Would create directory tree: %s", absPath)
		}
		return &sdkprovider.Output{
			Data: map[string]any{
				"success":   true,
				"operation": "mkdir",
				"path":      absPath,
				"_dryRun":   true,
				"_message":  msg,
			},
		}, nil

	case "rmdir":
		force, _ := inputs["force"].(bool)
		msg := fmt.Sprintf("Would remove directory: %s", absPath)
		if force {
			msg = fmt.Sprintf("Would force-remove directory and contents: %s", absPath)
		}
		return &sdkprovider.Output{
			Data: map[string]any{
				"success":   true,
				"operation": "rmdir",
				"path":      absPath,
				"_dryRun":   true,
				"_message":  msg,
			},
		}, nil

	case "copy":
		destination, ok := inputs["destination"].(string)
		if !ok || destination == "" {
			return nil, fmt.Errorf("destination is required for copy operation")
		}
		relativeTo, _ := inputs["relativeTo"].(string)
		absDest, err := resolvePathRel(ctx, destination, relativeTo)
		if err != nil {
			return nil, fmt.Errorf("resolving copy destination: %w", err)
		}
		return &sdkprovider.Output{
			Data: map[string]any{
				"success":     true,
				"operation":   "copy",
				"path":        absPath,
				"destination": absDest,
				"_dryRun":     true,
				"_message":    fmt.Sprintf("Would copy %s to %s", absPath, absDest),
			},
		}, nil

	case "move":
		destination, ok := inputs["destination"].(string)
		if !ok || destination == "" {
			return nil, fmt.Errorf("destination is required for move operation")
		}
		relativeTo, _ := inputs["relativeTo"].(string)
		absDest, err := resolvePathRel(ctx, destination, relativeTo)
		if err != nil {
			return nil, fmt.Errorf("resolving move destination: %w", err)
		}
		return &sdkprovider.Output{
			Data: map[string]any{
				"success":     true,
				"operation":   "move",
				"path":        absPath,
				"destination": absDest,
				"_dryRun":     true,
				"_message":    fmt.Sprintf("Would move %s to %s", absPath, absDest),
			},
		}, nil

	default:
		return nil, fmt.Errorf("unsupported operation: %s", operation)
	}
}

// toInt converts a numeric value to int, handling both int and float64 (from JSON).
func toInt(v any) (int, error) {
	switch val := v.(type) {
	case int:
		return val, nil
	case int64:
		return int(val), nil
	case float64:
		return int(val), nil
	case json.Number:
		n, err := val.Int64()
		if err != nil {
			return 0, err
		}
		return int(n), nil
	default:
		return 0, fmt.Errorf("cannot convert %T to int", v)
	}
}

// toInt64 converts a numeric value to int64, handling both int and float64 (from JSON).
func toInt64(v any) (int64, error) {
	switch val := v.(type) {
	case int:
		return int64(val), nil
	case int64:
		return val, nil
	case float64:
		return int64(val), nil
	case json.Number:
		return val.Int64()
	default:
		return 0, fmt.Errorf("cannot convert %T to int64", v)
	}
}
