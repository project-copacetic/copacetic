package wiz

type WizFakeReport struct {
	// TODO: To confirm the actual structure according to the Wiz report structure
	OSType    string
	OSVersion string
	Arch      string
	Packages  []WizFakePackage
}

type WizFakePackage struct {
	Name             string
	InstalledVersion string
	FixedVersion     string
	VulnerabilityID  string
}

type WizErrorUnsupported struct {
	err error
}

func (e *WizErrorUnsupported) Error() string { return e.err.Error() }
