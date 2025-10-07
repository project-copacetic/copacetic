package types

import "errors"

// ErrNoUpdatesFound indicates that no package updates are available for the image.
var ErrNoUpdatesFound = errors.New("no package updates found for image")
