package buildkit

import "errors"

// ErrOriginIntegrity marks a failure to validate or recover a recorded patch
// origin. Callers must not fall back to patching the current image on this error.
// Ordinary source resolution and unrelated build errors do not carry this marker.
var ErrOriginIntegrity = errors.New("patch origin integrity validation failed")
