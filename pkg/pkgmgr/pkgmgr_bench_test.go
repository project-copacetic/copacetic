package pkgmgr

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	log "github.com/sirupsen/logrus"
)

var (
	benchmarkUpdatesSink unversioned.UpdatePackages
	benchmarkStringsSink []string
	benchmarkMapSink     map[string]string
	benchmarkBytesSink   []byte
	benchmarkErrSink     error
)

var benchmarkComparer = VersionComparer{
	IsValid: func(v string) bool { return v != "" && !strings.Contains(v, "invalid") },
	LessThan: func(v1, v2 string) bool {
		return v1 < v2
	},
}

func silencePkgmgrBenchmarkLogs(b *testing.B) {
	b.Helper()
	oldLevel := log.GetLevel()
	log.SetLevel(log.PanicLevel)
	b.Cleanup(func() { log.SetLevel(oldLevel) })
}

func benchmarkUpdates(total, unique int) unversioned.UpdatePackages {
	updates := make(unversioned.UpdatePackages, total)
	for i := range updates {
		pkgIndex := i % unique
		updates[i] = unversioned.UpdatePackage{
			Name:         fmt.Sprintf("pkg%05d", pkgIndex),
			FixedVersion: fmt.Sprintf("1.0.%06d", i),
		}
	}
	return updates
}

func benchmarkPackageData(n int) map[string]string {
	packageInfo := make(map[string]string, n)
	for i := range n {
		packageInfo[fmt.Sprintf("pkg%05d", i)] = fmt.Sprintf("1.0.%06d", i)
	}
	return packageInfo
}

func benchmarkAPKResults(updates unversioned.UpdatePackages) []byte {
	var b strings.Builder
	for i := len(updates) - 1; i >= 0; i-- {
		u := updates[i]
		b.WriteString(u.Name)
		b.WriteByte('-')
		b.WriteString(u.FixedVersion)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func benchmarkPacmanResults(updates unversioned.UpdatePackages) []byte {
	var b strings.Builder
	for i := len(updates) - 1; i >= 0; i-- {
		u := updates[i]
		b.WriteString(u.Name)
		b.WriteByte(' ')
		b.WriteString(u.FixedVersion)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func benchmarkRPMResults(updates unversioned.UpdatePackages) []byte {
	var b strings.Builder
	for i := len(updates) - 1; i >= 0; i-- {
		u := updates[i]
		b.WriteString(u.Name)
		b.WriteByte('\t')
		b.WriteString(u.FixedVersion)
		b.WriteString("\tx86_64\n")
	}
	return []byte(b.String())
}

func benchmarkDPKGResults(updates unversioned.UpdatePackages) []byte {
	var b strings.Builder
	for _, u := range updates {
		b.WriteString("Package: ")
		b.WriteString(u.Name)
		b.WriteByte('\n')
		b.WriteString("Version: ")
		b.WriteString(u.FixedVersion)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func BenchmarkValidateOSPackageNames1000(b *testing.B) {
	updates := benchmarkUpdates(1000, 1000)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		benchmarkErrSink = ValidateOSPackageNames(updates)
	}
}

func BenchmarkGetUniqueLatestUpdates5000(b *testing.B) {
	updates := benchmarkUpdates(5000, 1000)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		benchmarkUpdatesSink, benchmarkErrSink = GetUniqueLatestUpdates(updates, benchmarkComparer, false)
	}
}

func BenchmarkValidateAPKPackageVersions1000(b *testing.B) {
	silencePkgmgrBenchmarkLogs(b)
	updates := benchmarkUpdates(1000, 1000)
	results := benchmarkAPKResults(updates)
	b.ReportAllocs()
	b.SetBytes(int64(len(results)))
	b.ResetTimer()
	for range b.N {
		benchmarkStringsSink, benchmarkErrSink = validateAPKPackageVersions(updates, benchmarkComparer, results, false)
	}
}

func BenchmarkValidatePacmanPackageVersions1000(b *testing.B) {
	silencePkgmgrBenchmarkLogs(b)
	updates := benchmarkUpdates(1000, 1000)
	results := benchmarkPacmanResults(updates)
	b.ReportAllocs()
	b.SetBytes(int64(len(results)))
	b.ResetTimer()
	for range b.N {
		benchmarkStringsSink, benchmarkErrSink = validatePacmanPackageVersions(updates, benchmarkComparer, results, false)
	}
}

func BenchmarkValidateRPMPackageVersions1000(b *testing.B) {
	silencePkgmgrBenchmarkLogs(b)
	updates := benchmarkUpdates(1000, 1000)
	results := benchmarkRPMResults(updates)
	b.ReportAllocs()
	b.SetBytes(int64(len(results)))
	b.ResetTimer()
	for range b.N {
		benchmarkStringsSink, benchmarkErrSink = validateRPMPackageVersions(updates, benchmarkComparer, results, false)
	}
}

func BenchmarkValidateDebianPackageVersions1000(b *testing.B) {
	silencePkgmgrBenchmarkLogs(b)
	updates := benchmarkUpdates(1000, 1000)
	results := benchmarkDPKGResults(updates)
	b.ReportAllocs()
	b.SetBytes(int64(len(results)))
	b.ResetTimer()
	for range b.N {
		benchmarkStringsSink, benchmarkErrSink = validateDebianPackageVersions(updates, benchmarkComparer, results, false)
	}
}

func BenchmarkParseDPKGResultsManifest1000(b *testing.B) {
	results := benchmarkDPKGResults(benchmarkUpdates(1000, 1000))
	b.ReportAllocs()
	b.SetBytes(int64(len(results)))
	b.ResetTimer()
	for range b.N {
		benchmarkMapSink, benchmarkErrSink = dpkgParseResultsManifest(results)
	}
}

func BenchmarkParseRPMManifestFile1000(b *testing.B) {
	results := string(benchmarkRPMResults(benchmarkUpdates(1000, 1000)))
	b.ReportAllocs()
	b.SetBytes(int64(len(results)))
	b.ResetTimer()
	for range b.N {
		benchmarkMapSink, benchmarkErrSink = parseManifestFile(results)
	}
}

func BenchmarkGetJSONPackageData1000(b *testing.B) {
	packageInfo := benchmarkPackageData(1000)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		benchmarkBytesSink, benchmarkErrSink = getJSONPackageData(packageInfo)
	}
}

func BenchmarkParseRPMTools(b *testing.B) {
	var tools strings.Builder
	for i := range 1000 {
		tools.WriteString("tool")
		tools.WriteString(strconv.Itoa(i))
		tools.WriteString(":/usr/bin/tool")
		tools.WriteString(strconv.Itoa(i))
		tools.WriteByte('\n')
	}
	input := []byte(tools.String())
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for range b.N {
		_, benchmarkErrSink = parseRPMTools(input)
	}
}
