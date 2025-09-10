package pkgmgr

import "errors"

// Returned by managers when the image has no packages to upgrade.
var ErrNoUpdatesFound = errors.New("no package updates found for image")
