# Fuzzing in Copacetic

This document describes the fuzzing implementation in Copacetic, which was added to improve the security and robustness of the codebase, particularly for parsing external data from vulnerability scanners and package managers.

## Overview

Copacetic includes fuzz tests using Go's built-in fuzzing support (introduced in Go 1.18) to test critical functions with randomly generated inputs. This helps identify potential crashes, security vulnerabilities, and edge cases that might not be covered by traditional unit tests.

## What is Fuzzed

### Package Report (`pkg/report`)
- **FuzzTrivyParser**: Tests the Trivy vulnerability report parser
- **FuzzParseTrivyReport**: Tests low-level Trivy JSON parsing
- **FuzzCustomParseScanReport**: Tests custom scanner report parsing
- **FuzzJSONUnmarshal**: Tests JSON unmarshaling with various data types

### Package Manager (`pkg/pkgmgr`)
- **FuzzDebianVersionValidation**: Tests Debian package version validation
- **FuzzDebianVersionComparison**: Tests Debian version comparison logic
- **FuzzRPMVersionComparison**: Tests RPM version comparison logic
- **FuzzAPKVersionValidation**: Tests Alpine package version validation
- **FuzzAPKVersionComparison**: Tests Alpine version comparison logic
- **FuzzAPKResultsManifest**: Tests APK results manifest parsing

### Utils (`pkg/utils`)
- **FuzzEOLAPIResponseParsing**: Tests End-of-Life API response parsing
- **FuzzPodmanInspectParsing**: Tests podman inspect output parsing
- **FuzzGenericJSONMapParsing**: Tests generic JSON to map parsing
- **FuzzEOLProductInfoParsing**: Tests EOL product info parsing
- **FuzzStringArrayParsing**: Tests string array parsing from JSON

## Running Fuzz Tests

### Local Development

```bash
# Run short fuzz tests (5 seconds each)
make fuzz-short

# Run extended fuzz tests (30 seconds each)
make fuzz

# Run a specific fuzz test
go test -fuzz=FuzzTrivyParser -fuzztime=10s ./pkg/report

# Run all fuzz tests in a package
go test -fuzz=. -fuzztime=5s ./pkg/pkgmgr
```

### CI/CD Integration

Fuzz tests are automatically run in GitHub Actions:
- **Pull Requests**: Short fuzz tests (5 seconds each)
- **Push to main**: Short fuzz tests (5 seconds each)
- **Daily Schedule**: Extended fuzz tests (30 seconds each)

See `.github/workflows/fuzz.yml` for the complete workflow.

## Writing New Fuzz Tests

When adding new fuzz tests, follow these guidelines:

1. **File naming**: Use `*_fuzz_test.go` or add fuzz functions to existing `*_test.go` files
2. **Function naming**: Start with `FuzzXxx` where `Xxx` describes what's being fuzzed
3. **Panic protection**: Always use defer/recover to catch panics
4. **Seed corpus**: Add meaningful seed inputs using `f.Add()`
5. **Focus on robustness**: Don't assert correctness, focus on preventing crashes

Example:
```go
func FuzzMyParser(f *testing.F) {
    // Add seed corpus
    f.Add([]byte(`{"valid": "json"}`))
    f.Add([]byte(`{}`))
    f.Add([]byte(`invalid`))

    f.Fuzz(func(t *testing.T, data []byte) {
        // Catch panics
        defer func() {
            if r := recover(); r != nil {
                t.Errorf("MyParser panicked: %v", r)
            }
        }()

        // Test the function
        _, _ = MyParser(data)
    })
}
```

## Handling Fuzz Failures

When fuzz tests find issues:

1. **Crashes/Panics**: These should be fixed as they indicate robustness issues
2. **Infinite loops**: Use timeouts and consider input validation
3. **Memory issues**: Profile and optimize memory usage
4. **False positives**: Update the fuzz test to handle expected error conditions

Fuzz failures are saved in `testdata/fuzz/` directories and can be replayed:
```bash
go test -run=FuzzMyFunction/specific_failure_case
```

## Benefits

Fuzzing provides several benefits:
- **Security**: Finds potential security vulnerabilities in input parsing
- **Robustness**: Identifies edge cases that cause crashes
- **Coverage**: Tests code paths that might not be covered by unit tests
- **Regression prevention**: Prevents introduction of new parsing bugs

## OpenSSF Scorecard

This fuzzing implementation addresses the OpenSSF Scorecard "Fuzzing" check, improving the project's security posture and demonstrating commitment to robust software development practices.