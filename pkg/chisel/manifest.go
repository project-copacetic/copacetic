package chisel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	chiselmanifest "github.com/canonical/chisel-manifest/public/manifest"
	"github.com/klauspost/compress/zstd"
)

const (
	// MaxManifestSize is the maximum decompressed size accepted for a native
	// Chisel manifest.wall file.
	MaxManifestSize = 64 << 20

	// maxManifestRecords is the maximum number of JSONWall records, including
	// the header, accepted within MaxManifestSize. The 1 KiB structural budget
	// per record bounds retained indexes and decoded metadata for compact,
	// adversarial manifests well below the byte-size limit.
	maxManifestRecords = MaxManifestSize / (1 << 10)

	// These limits bound the memory retained while checking top-level JSON
	// object fields. Canonical schema 1.0 records use far fewer members and key
	// bytes, leaving ample room for additive schema fields.
	maxJSONObjectMembers  = 256
	maxJSONObjectKeyBytes = 16 << 10
)

var (
	packageNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	sliceNamePattern   = regexp.MustCompile(`^([a-z0-9][a-z0-9+.-]+)_([a-z](?:-?[a-z0-9]){2,})$`)
)

// Package describes an installed Debian package recorded in a Chisel manifest.
type Package struct {
	Name         string
	Version      string
	SHA256       string
	Architecture string
}

// PathMetadata describes a filesystem path owned by one or more selected
// Chisel slices.
type PathMetadata struct {
	Path        string
	Mode        fs.FileMode
	Slices      []string
	SHA256      string
	FinalSHA256 string
	Size        uint64
	Link        string
	Inode       uint64
}

// Digest returns the digest expected for the final filesystem contents.
//
//nolint:gocritic // A value receiver keeps map-indexed metadata convenient to use.
func (metadata PathMetadata) Digest() string {
	if metadata.FinalSHA256 != "" {
		return metadata.FinalSHA256
	}
	return metadata.SHA256
}

// IsDir reports whether the manifest path represents a directory.
//
//nolint:gocritic // A value receiver keeps map-indexed metadata convenient to use.
func (metadata PathMetadata) IsDir() bool {
	return strings.HasSuffix(metadata.Path, "/")
}

// IsSymlink reports whether the manifest path represents a symbolic link.
//
//nolint:gocritic // A value receiver keeps map-indexed metadata convenient to use.
func (metadata PathMetadata) IsSymlink() bool {
	return !metadata.IsDir() && metadata.Link != ""
}

// IsRegular reports whether the manifest path represents a regular file.
//
//nolint:gocritic // A value receiver keeps map-indexed metadata convenient to use.
func (metadata PathMetadata) IsRegular() bool {
	return !metadata.IsDir() && metadata.Link == ""
}

// Manifest contains the validated package, slice, and managed-filesystem state
// extracted from a native Chisel manifest.wall file.
type Manifest struct {
	Packages   map[string]Package
	Slices     []string
	OwnedPaths map[string]PathMetadata
}

type jsonWallHeader struct {
	Version string `json:"jsonwall"`
	Schema  string `json:"schema"`
	Count   int    `json:"count"`
}

type recordEnvelope struct {
	Kind string `json:"kind"`
}

type manifestRecords struct {
	packages  map[string]Package
	slices    map[string]string
	paths     map[string]PathMetadata
	contents  map[string]map[string]struct{}
	hardLinks map[uint64][]PathMetadata
}

// ParseManifest reads, bounds, parses, and validates a zstd-compressed native
// Chisel manifest.wall stream.
func ParseManifest(reader io.Reader) (*Manifest, error) {
	if reader == nil {
		return nil, fmt.Errorf("cannot read native Chisel manifest: reader is nil")
	}

	data, err := decompressManifest(reader)
	if err != nil {
		return nil, err
	}

	result, err := parseManifestData(data)
	if err != nil {
		return nil, fmt.Errorf("invalid native Chisel manifest: %w", err)
	}
	return result, nil
}

func decompressManifest(reader io.Reader) ([]byte, error) {
	decoder, err := zstd.NewReader(
		reader,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderLowmem(true),
		zstd.WithDecoderMaxMemory(MaxManifestSize+1),
		zstd.WithDecoderMaxWindow(MaxManifestSize),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize native Chisel manifest decompressor: %w", err)
	}
	defer decoder.Close()

	data, err := io.ReadAll(io.LimitReader(decoder, MaxManifestSize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot decompress native Chisel manifest: %w", err)
	}
	if len(data) > MaxManifestSize {
		return nil, fmt.Errorf("native Chisel manifest exceeds the %d MiB decompressed size limit", MaxManifestSize>>20)
	}
	return data, nil
}

func parseManifestData(data []byte) (*Manifest, error) {
	headerLine, remaining, ok := nextJSONWallLine(data)
	if !ok || len(headerLine) == 0 {
		return nil, fmt.Errorf("missing JSONWall header")
	}
	if !bytes.Equal(headerLine, bytes.TrimSpace(headerLine)) {
		return nil, fmt.Errorf("JSONWall header contains leading or trailing whitespace")
	}

	if err := validateUniqueJSONFields(headerLine, jsonObjectValidationOptions{}); err != nil {
		return nil, fmt.Errorf("cannot decode JSONWall header: %w", err)
	}

	var header jsonWallHeader
	if err := json.Unmarshal(headerLine, &header); err != nil {
		return nil, fmt.Errorf("cannot decode JSONWall header: %w", err)
	}
	if !isJSONWallMajorOne(header.Version) {
		return nil, fmt.Errorf("unsupported JSONWall version %q; expected major version 1", header.Version)
	}
	if header.Schema != chiselmanifest.Schema {
		return nil, fmt.Errorf("unsupported Chisel manifest schema %q; expected %q", header.Schema, chiselmanifest.Schema)
	}
	if header.Count < 1 {
		return nil, fmt.Errorf("invalid JSONWall record count %d", header.Count)
	}
	if header.Count > maxManifestRecords {
		return nil, fmt.Errorf(
			"JSONWall header record count %d exceeds the structural limit of %d records",
			header.Count,
			maxManifestRecords,
		)
	}

	physicalCount := countJSONWallRecords(data)
	if physicalCount > maxManifestRecords {
		return nil, fmt.Errorf(
			"native Chisel manifest contains %d JSONWall records, exceeding the structural limit of %d records",
			physicalCount,
			maxManifestRecords,
		)
	}

	records := manifestRecords{
		packages:  make(map[string]Package),
		slices:    make(map[string]string),
		paths:     make(map[string]PathMetadata),
		contents:  make(map[string]map[string]struct{}),
		hardLinks: make(map[uint64][]PathMetadata),
	}

	actualCount := 1
	var previousLine []byte
	for len(remaining) > 0 {
		line, rest, _ := nextJSONWallLine(remaining)
		remaining = rest
		actualCount++

		if len(line) == 0 {
			return nil, fmt.Errorf("JSONWall record %d is empty", actualCount)
		}
		if !bytes.Equal(line, bytes.TrimSpace(line)) {
			return nil, fmt.Errorf("JSONWall record %d contains leading or trailing whitespace", actualCount)
		}
		if !bytes.HasPrefix(line, []byte(`{"kind":`)) {
			return nil, fmt.Errorf("JSONWall record %d must begin with the kind field", actualCount)
		}
		if previousLine != nil && bytes.Compare(previousLine, line) > 0 {
			return nil, fmt.Errorf("JSONWall records %d and %d are not sorted", actualCount-1, actualCount)
		}
		previousLine = line

		// JSONWall records are sorted, and path records sort before slice
		// records. Every slice that can own this path must therefore occupy one
		// of the record slots after the current path record. Use the smaller of
		// the declared and physical counts while the final count check is pending.
		maxPossibleSliceRecords := max(min(header.Count, physicalCount)-actualCount, 0)
		if err := records.addRecord(line, actualCount, maxPossibleSliceRecords); err != nil {
			return nil, err
		}
	}

	if actualCount != header.Count {
		return nil, fmt.Errorf("JSONWall header count is %d, but manifest contains %d records", header.Count, actualCount)
	}

	// chiselmanifest.Read would copy data and build a second full record index.
	// Its JSONWall version and schema compatibility checks are already enforced
	// above, and individual records are decoded with Canonical's public types.
	return records.validateAndExtract()
}

func countJSONWallRecords(data []byte) int {
	count := bytes.Count(data, []byte{'\n'})
	if len(data) > 0 && data[len(data)-1] != '\n' {
		count++
	}
	return count
}

func nextJSONWallLine(data []byte) (line, remaining []byte, terminated bool) {
	if len(data) == 0 {
		return nil, nil, false
	}
	index := bytes.IndexByte(data, '\n')
	if index < 0 {
		return data, nil, false
	}
	return data[:index], data[index+1:], true
}

func isJSONWallMajorOne(version string) bool {
	major, _, found := strings.Cut(version, ".")
	return found && major == "1"
}

type jsonObjectValidationOptions struct {
	validatePathSlices bool
	maxPathSlices      int
}

// validateUniqueJSONFields rejects ambiguous top-level object members before
// encoding/json can apply its case-insensitive, last-value-wins behavior. For
// records, it also streams a path record's slices array so its relationship-
// aware bound is enforced before typed unmarshalling allocates []string.
func validateUniqueJSONFields(data []byte, options jsonObjectValidationOptions) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return fmt.Errorf("expected JSON object")
	}

	fields := make(map[string]string)
	memberCount := 0
	keyBytes := 0
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return err
		}
		field, ok := token.(string)
		if !ok {
			return fmt.Errorf("expected JSON field name")
		}

		memberCount++
		if memberCount > maxJSONObjectMembers {
			return fmt.Errorf(
				"JSON object top-level member count %d exceeds the structural limit of %d members",
				memberCount,
				maxJSONObjectMembers,
			)
		}
		keyBytes += len(field)
		if keyBytes > maxJSONObjectKeyBytes {
			return fmt.Errorf(
				"JSON object field names use %d bytes, exceeding the structural limit of %d bytes",
				keyBytes,
				maxJSONObjectKeyBytes,
			)
		}

		foldedField := foldJSONFieldName(field)
		if previousField, exists := fields[foldedField]; exists {
			if previousField == field {
				return fmt.Errorf("duplicate JSON field %q", field)
			}
			return fmt.Errorf(
				"duplicate JSON field %q via case-insensitive alias %q",
				previousField,
				field,
			)
		}
		fields[foldedField] = field

		switch {
		case options.validatePathSlices && foldedField == "SLICES":
			if err := validatePathSlicesArray(decoder, options.maxPathSlices); err != nil {
				return err
			}
		default:
			var value json.RawMessage
			if err := decoder.Decode(&value); err != nil {
				return err
			}
		}
	}

	if _, err := decoder.Token(); err != nil {
		return err
	}
	if token, err = decoder.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("unexpected JSON token %v after object", token)
	}
	return nil
}

func validatePathSlicesArray(decoder *json.Decoder, maxSlices int) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf(`cannot decode path record "slices" field: %w`, err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '[' {
		return fmt.Errorf(`path record "slices" field must be an array`)
	}

	count := 0
	for decoder.More() {
		count++
		if count > maxSlices {
			return fmt.Errorf(
				`path record "slices" array contains %d entries; at most %d slice records can follow this path record`,
				count,
				maxSlices,
			)
		}

		var sliceName string
		if err := decoder.Decode(&sliceName); err != nil {
			return fmt.Errorf(`cannot decode path record "slices" entry %d as a string: %w`, count, err)
		}
	}
	closingToken, err := decoder.Token()
	if err != nil {
		return fmt.Errorf(`cannot decode path record "slices" field: %w`, err)
	}
	if closingDelimiter, ok := closingToken.(json.Delim); !ok || closingDelimiter != ']' {
		return fmt.Errorf(`path record "slices" field has an invalid array terminator`)
	}
	return nil
}

// foldJSONFieldName mirrors encoding/json's case folding so fields that target
// the same decoded struct member share one map key.
func foldJSONFieldName(field string) string {
	var buffer [32]byte
	folded := buffer[:0]
	for index := 0; index < len(field); {
		character := field[index]
		if character < utf8.RuneSelf {
			if 'a' <= character && character <= 'z' {
				character -= 'a' - 'A'
			}
			folded = append(folded, character)
			index++
			continue
		}

		characterRune, size := utf8.DecodeRuneInString(field[index:])
		folded = utf8.AppendRune(folded, foldJSONFieldRune(characterRune))
		index += size
	}
	return string(folded)
}

func foldJSONFieldRune(character rune) rune {
	for {
		next := unicode.SimpleFold(character)
		if next <= character {
			return next
		}
		character = next
	}
}

func (records *manifestRecords) addRecord(line []byte, recordNumber, maxPathSlices int) error {
	var envelope recordEnvelope
	if err := json.Unmarshal(line, &envelope); err != nil {
		return fmt.Errorf("cannot decode JSONWall record %d: %w", recordNumber, err)
	}
	if err := validateUniqueJSONFields(line, jsonObjectValidationOptions{
		validatePathSlices: envelope.Kind == "path",
		maxPathSlices:      maxPathSlices,
	}); err != nil {
		return fmt.Errorf("cannot decode JSONWall record %d: %w", recordNumber, err)
	}

	switch envelope.Kind {
	case "package":
		return records.addPackage(line)
	case "slice":
		return records.addSlice(line)
	case "content":
		return records.addContent(line)
	case "path":
		return records.addPath(line)
	case "":
		return fmt.Errorf("JSONWall record %d is missing kind", recordNumber)
	default:
		return fmt.Errorf("JSONWall record %d has unsupported kind %q", recordNumber, envelope.Kind)
	}
}

func (records *manifestRecords) addPackage(line []byte) error {
	var record chiselmanifest.Package
	if err := json.Unmarshal(line, &record); err != nil {
		return fmt.Errorf("cannot decode package record: %w", err)
	}
	if !packageNamePattern.MatchString(record.Name) {
		return fmt.Errorf("invalid Debian package name %q", record.Name)
	}
	if record.Version == "" {
		return fmt.Errorf("package %q is missing version", record.Name)
	}
	if err := validateSHA256(record.Digest); err != nil {
		return fmt.Errorf("package %q has invalid sha256: %w", record.Name, err)
	}
	if record.Arch == "" {
		return fmt.Errorf("package %q is missing architecture", record.Name)
	}
	if _, exists := records.packages[record.Name]; exists {
		return fmt.Errorf("duplicate package record %q", record.Name)
	}

	records.packages[record.Name] = Package{
		Name:         record.Name,
		Version:      record.Version,
		SHA256:       record.Digest,
		Architecture: record.Arch,
	}
	return nil
}

func (records *manifestRecords) addSlice(line []byte) error {
	var record chiselmanifest.Slice
	if err := json.Unmarshal(line, &record); err != nil {
		return fmt.Errorf("cannot decode slice record: %w", err)
	}
	packageName, err := packageForSlice(record.Name)
	if err != nil {
		return err
	}
	if _, exists := records.slices[record.Name]; exists {
		return fmt.Errorf("duplicate slice record %q", record.Name)
	}
	records.slices[record.Name] = packageName
	return nil
}

func (records *manifestRecords) addContent(line []byte) error {
	var record chiselmanifest.Content
	if err := json.Unmarshal(line, &record); err != nil {
		return fmt.Errorf("cannot decode content record: %w", err)
	}
	if _, err := packageForSlice(record.Slice); err != nil {
		return fmt.Errorf("content record has invalid slice: %w", err)
	}
	if err := validateManifestPath(record.Path); err != nil {
		return fmt.Errorf("content record has invalid path %q: %w", record.Path, err)
	}

	if records.contents[record.Path] == nil {
		records.contents[record.Path] = make(map[string]struct{})
	}
	if _, exists := records.contents[record.Path][record.Slice]; exists {
		return fmt.Errorf("duplicate content record for slice %q and path %q", record.Slice, record.Path)
	}
	records.contents[record.Path][record.Slice] = struct{}{}
	return nil
}

func (records *manifestRecords) addPath(line []byte) error {
	var record chiselmanifest.Path
	if err := json.Unmarshal(line, &record); err != nil {
		return fmt.Errorf("cannot decode path record: %w", err)
	}
	if err := validateManifestPath(record.Path); err != nil {
		return fmt.Errorf("path record %q is invalid: %w", record.Path, err)
	}
	if _, exists := records.paths[record.Path]; exists {
		return fmt.Errorf("duplicate path record %q", record.Path)
	}

	mode, err := parseMode(record.Mode)
	if err != nil {
		return fmt.Errorf("path %q has invalid mode %q: %w", record.Path, record.Mode, err)
	}
	if len(record.Slices) == 0 {
		return fmt.Errorf("path %q has no owning slices", record.Path)
	}

	pathSlices := make([]string, 0, len(record.Slices))
	seenSlices := make(map[string]struct{}, len(record.Slices))
	for _, sliceName := range record.Slices {
		if _, err := packageForSlice(sliceName); err != nil {
			return fmt.Errorf("path %q has invalid slice: %w", record.Path, err)
		}
		if _, exists := seenSlices[sliceName]; exists {
			return fmt.Errorf("path %q lists slice %q more than once", record.Path, sliceName)
		}
		seenSlices[sliceName] = struct{}{}
		pathSlices = append(pathSlices, sliceName)
	}
	slices.Sort(pathSlices)

	metadata := PathMetadata{
		Path:        record.Path,
		Mode:        mode,
		Slices:      pathSlices,
		SHA256:      record.SHA256,
		FinalSHA256: record.FinalSHA256,
		Size:        record.Size,
		Link:        record.Link,
		Inode:       record.Inode,
	}
	if err := validatePathMetadata(&metadata); err != nil {
		return err
	}

	records.paths[record.Path] = metadata
	if metadata.Inode != 0 {
		records.hardLinks[metadata.Inode] = append(records.hardLinks[metadata.Inode], metadata)
	}
	return nil
}

func (records *manifestRecords) validateAndExtract() (*Manifest, error) {
	if len(records.packages) == 0 {
		return nil, fmt.Errorf("manifest contains no package records")
	}
	if len(records.slices) == 0 {
		return nil, fmt.Errorf("manifest contains no slice records")
	}
	if len(records.paths) == 0 {
		return nil, fmt.Errorf("manifest contains no path records")
	}

	for sliceName, packageName := range records.slices {
		if _, exists := records.packages[packageName]; !exists {
			return nil, fmt.Errorf("slice %q refers to missing package %q", sliceName, packageName)
		}
	}

	for contentPath, contentSlices := range records.contents {
		if _, exists := records.paths[contentPath]; !exists {
			return nil, fmt.Errorf("content path %q has no matching path record", contentPath)
		}
		for sliceName := range contentSlices {
			if _, exists := records.slices[sliceName]; !exists {
				return nil, fmt.Errorf("content path %q refers to missing slice %q", contentPath, sliceName)
			}
		}
	}

	for ownedPath, metadata := range records.paths {
		for _, sliceName := range metadata.Slices {
			if _, exists := records.slices[sliceName]; !exists {
				return nil, fmt.Errorf("path %q refers to missing slice %q", ownedPath, sliceName)
			}
		}

		contentSlices, exists := records.contents[ownedPath]
		if !exists {
			return nil, fmt.Errorf("path %q has no matching content record", ownedPath)
		}
		if !sameSliceSet(metadata.Slices, contentSlices) {
			return nil, fmt.Errorf("path %q and its content records refer to different slices", ownedPath)
		}
	}

	if err := validateHardLinks(records.hardLinks); err != nil {
		return nil, err
	}

	sliceNames := make([]string, 0, len(records.slices))
	for sliceName := range records.slices {
		sliceNames = append(sliceNames, sliceName)
	}
	slices.Sort(sliceNames)

	return &Manifest{
		Packages:   records.packages,
		Slices:     sliceNames,
		OwnedPaths: records.paths,
	}, nil
}

func packageForSlice(sliceName string) (string, error) {
	matches := sliceNamePattern.FindStringSubmatch(sliceName)
	if matches == nil {
		return "", fmt.Errorf("invalid Chisel slice name %q", sliceName)
	}
	return matches[1], nil
}

func validateManifestPath(manifestPath string) error {
	if manifestPath == "" {
		return fmt.Errorf("path is empty")
	}
	if strings.IndexByte(manifestPath, 0) >= 0 {
		return fmt.Errorf("path contains a NUL byte")
	}
	if strings.ContainsFunc(manifestPath, unicode.IsControl) {
		return fmt.Errorf("path contains a control character")
	}
	if !path.IsAbs(manifestPath) {
		return fmt.Errorf("path must be absolute")
	}

	pathWithoutDirectorySlash := manifestPath
	if manifestPath != "/" && strings.HasSuffix(manifestPath, "/") {
		pathWithoutDirectorySlash = strings.TrimSuffix(manifestPath, "/")
	}
	if path.Clean(pathWithoutDirectorySlash) != pathWithoutDirectorySlash {
		return fmt.Errorf("path must be normalized and must not contain traversal")
	}
	return nil
}

func parseMode(value string) (fs.FileMode, error) {
	if len(value) < 2 || len(value) > 5 || value[0] != '0' {
		return 0, fmt.Errorf("mode must be a zero-prefixed octal permission")
	}
	parsed, err := strconv.ParseUint(value, 8, 16)
	if err != nil {
		return 0, fmt.Errorf("mode must be octal: %w", err)
	}
	if parsed&^uint64(0o7777) != 0 {
		return 0, fmt.Errorf("mode contains unsupported bits")
	}
	return fs.FileMode(parsed), nil
}

func validatePathMetadata(metadata *PathMetadata) error {
	if metadata.SHA256 != "" {
		if err := validateSHA256(metadata.SHA256); err != nil {
			return fmt.Errorf("path %q has invalid sha256: %w", metadata.Path, err)
		}
	}
	if metadata.FinalSHA256 != "" {
		if metadata.SHA256 == "" {
			return fmt.Errorf("path %q has final_sha256 without sha256", metadata.Path)
		}
		if err := validateSHA256(metadata.FinalSHA256); err != nil {
			return fmt.Errorf("path %q has invalid final_sha256: %w", metadata.Path, err)
		}
	}

	switch {
	case metadata.IsDir():
		if metadata.Link != "" || metadata.SHA256 != "" || metadata.FinalSHA256 != "" || metadata.Size != 0 || metadata.Inode != 0 {
			return fmt.Errorf("directory path %q contains regular-file or link metadata", metadata.Path)
		}
	case metadata.IsSymlink():
		if strings.IndexByte(metadata.Link, 0) >= 0 {
			return fmt.Errorf("symlink path %q has a target containing a NUL byte", metadata.Path)
		}
		if metadata.SHA256 != "" || metadata.FinalSHA256 != "" || metadata.Size != 0 {
			return fmt.Errorf("symlink path %q contains regular-file metadata", metadata.Path)
		}
	case metadata.Inode != 0 && metadata.SHA256 == "":
		return fmt.Errorf("hard-linked path %q is missing sha256", metadata.Path)
	}
	return nil
}

func validateSHA256(value string) error {
	if len(value) != 64 {
		return fmt.Errorf("must contain 64 lowercase hexadecimal characters")
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return fmt.Errorf("must contain 64 lowercase hexadecimal characters")
		}
	}
	return nil
}

func sameSliceSet(pathSlices []string, contentSlices map[string]struct{}) bool {
	if len(pathSlices) != len(contentSlices) {
		return false
	}
	for _, sliceName := range pathSlices {
		if _, exists := contentSlices[sliceName]; !exists {
			return false
		}
	}
	return true
}

func validateHardLinks(groups map[uint64][]PathMetadata) error {
	if len(groups) == 0 {
		return nil
	}

	identifiers := make([]uint64, 0, len(groups))
	for identifier := range groups {
		identifiers = append(identifiers, identifier)
	}
	slices.Sort(identifiers)

	for index, identifier := range identifiers {
		expected := uint64(index + 1)
		if identifier != expected {
			return fmt.Errorf("hard-link group %d is missing before group %d", expected, identifier)
		}
		group := groups[identifier]
		if len(group) < 2 {
			return fmt.Errorf("hard-link group %d contains only path %q", identifier, group[0].Path)
		}

		first := group[0]
		if !first.IsRegular() && !first.IsSymlink() {
			return fmt.Errorf("hard-link group %d contains unsupported path %q", identifier, first.Path)
		}
		for _, candidate := range group[1:] {
			if first.IsRegular() != candidate.IsRegular() || first.IsSymlink() != candidate.IsSymlink() {
				return fmt.Errorf(
					"hard-link group %d mixes regular and symlink paths %q and %q",
					identifier,
					first.Path,
					candidate.Path,
				)
			}
			if candidate.Mode != first.Mode || candidate.Link != first.Link ||
				candidate.SHA256 != first.SHA256 || candidate.FinalSHA256 != first.FinalSHA256 || candidate.Size != first.Size {
				return fmt.Errorf("hard-linked paths %q and %q have inconsistent metadata", first.Path, candidate.Path)
			}
		}
	}
	return nil
}
