package generate

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func BenchmarkCreateTarStreamWithSparseHardlinks(b *testing.B) {
	patchLayer := benchmarkPatchLayer(b, 1000, 4096, 10)
	outDir := b.TempDir()
	originalOutput := log.StandardLogger().Out
	log.SetOutput(io.Discard)
	defer log.SetOutput(originalOutput)

	b.ReportAllocs()
	b.SetBytes(int64(len(patchLayer)))
	for i := 0; i < b.N; i++ {
		outputPath := filepath.Join(outDir, fmt.Sprintf("context-%06d.tar", i))
		if err := createTarStream("debian:12", patchLayer, outputPath); err != nil {
			b.Fatal(err)
		}
		if err := os.Remove(outputPath); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkPatchLayer(b *testing.B, regularFiles, fileSize, hardlinks int) []byte {
	b.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	modTime := time.Unix(1700000000, 0).UTC()
	content := bytes.Repeat([]byte("x"), fileSize)

	for i := 0; i < regularFiles; i++ {
		name := fmt.Sprintf("usr/lib/bench/file-%06d.dat", i)
		hdr := &tar.Header{
			Name:    name,
			Mode:    0o644,
			Size:    int64(len(content)),
			ModTime: modTime,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			b.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			b.Fatal(err)
		}
	}

	for i := 0; i < hardlinks; i++ {
		hdr := &tar.Header{
			Name:     fmt.Sprintf("usr/bin/bench-link-%06d", i),
			Mode:     0o755,
			Linkname: fmt.Sprintf("usr/lib/bench/file-%06d.dat", i*(regularFiles/hardlinks)),
			ModTime:  modTime,
			Typeflag: tar.TypeLink,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			b.Fatal(err)
		}
	}

	if err := tw.Close(); err != nil {
		b.Fatal(err)
	}
	return buf.Bytes()
}
