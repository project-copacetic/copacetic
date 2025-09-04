package pkgmgr

import (
	"testing"
)

// FuzzDebianVersionValidation tests isValidDebianVersion with random version strings
func FuzzDebianVersionValidation(f *testing.F) {
	// Add seed corpus with known valid and invalid Debian versions
	f.Add("1.0.0")
	f.Add("1:2.3.4-5")
	f.Add("2.3.4-5ubuntu1")
	f.Add("1.2.3+dfsg-1")
	f.Add("2:1.0-1~deb9u1")
	f.Add("")
	f.Add("invalid")
	f.Add("1.0.0.0.0.0.0")
	f.Add("1.2.3-")
	f.Add("-1.2.3")

	f.Fuzz(func(t *testing.T, version string) {
		// Should not panic on any input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("isValidDebianVersion panicked with input %q: %v", version, r)
			}
		}()

		// Just call the function, we don't assert the result
		_ = isValidDebianVersion(version)
	})
}

// FuzzDebianVersionComparison tests isLessThanDebianVersion with random version pairs
func FuzzDebianVersionComparison(f *testing.F) {
	// Add seed corpus with version pairs
	f.Add("1.0", "2.0")
	f.Add("1:2.0", "1:3.0")
	f.Add("1.0-1", "1.0-2")
	f.Add("1.0", "1.0")
	f.Add("", "")
	f.Add("invalid", "version")

	f.Fuzz(func(t *testing.T, v1, v2 string) {
		// Should not panic on any input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("isLessThanDebianVersion panicked with inputs %q, %q: %v", v1, v2, r)
			}
		}()

		// Just call the function, we don't assert the result
		_ = isLessThanDebianVersion(v1, v2)
	})
}

// FuzzRPMVersionComparison tests isLessThanRPMVersion with random version pairs
func FuzzRPMVersionComparison(f *testing.F) {
	// Add seed corpus with RPM version pairs
	f.Add("1.0", "2.0")
	f.Add("1.0-1", "1.0-2")
	f.Add("1.0-1.el7", "1.0-2.el7")
	f.Add("2:1.0", "2:2.0")
	f.Add("1.0", "1.0")
	f.Add("", "")
	f.Add("invalid", "version")

	f.Fuzz(func(t *testing.T, v1, v2 string) {
		// Should not panic on any input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("isLessThanRPMVersion panicked with inputs %q, %q: %v", v1, v2, r)
			}
		}()

		// Just call the function, we don't assert the result
		_ = isLessThanRPMVersion(v1, v2)
	})
}

// FuzzAPKVersionValidation tests isValidAPKVersion with random version strings
func FuzzAPKVersionValidation(f *testing.F) {
	// Add seed corpus with known valid and invalid APK versions
	f.Add("1.0.0")
	f.Add("1.0.0-r1")
	f.Add("2.3.4_alpha1")
	f.Add("1.0_pre20200101")
	f.Add("1.0_rc1")
	f.Add("")
	f.Add("invalid")
	f.Add("1.0.0.0.0.0.0")
	f.Add("1.0-")
	f.Add("-1.0")

	f.Fuzz(func(t *testing.T, version string) {
		// Should not panic on any input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("isValidAPKVersion panicked with input %q: %v", version, r)
			}
		}()

		// Just call the function, we don't assert the result
		_ = isValidAPKVersion(version)
	})
}

// FuzzAPKVersionComparison tests isLessThanAPKVersion with random version pairs
func FuzzAPKVersionComparison(f *testing.F) {
	// Add seed corpus with APK version pairs
	f.Add("1.0", "2.0")
	f.Add("1.0-r1", "1.0-r2")
	f.Add("1.0_alpha1", "1.0_alpha2")
	f.Add("1.0", "1.0")
	f.Add("", "")
	f.Add("invalid", "version")

	f.Fuzz(func(t *testing.T, v1, v2 string) {
		// Should not panic on any input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("isLessThanAPKVersion panicked with inputs %q, %q: %v", v1, v2, r)
			}
		}()

		// Just call the function, we don't assert the result
		_ = isLessThanAPKVersion(v1, v2)
	})
}

// FuzzAPKResultsManifest tests apkReadResultsManifest with random byte data
func FuzzAPKResultsManifest(f *testing.F) {
	// Add seed corpus with various APK manifest formats
	f.Add([]byte("package1\npackage2\npackage3\n"))
	f.Add([]byte(""))
	f.Add([]byte("single-package"))
	f.Add([]byte("\n\n\n"))
	f.Add([]byte("package with spaces"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic on any input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("apkReadResultsManifest panicked: %v", r)
			}
		}()

		// Just call the function, we don't assert the result
		_, _ = apkReadResultsManifest(data)
	})
}