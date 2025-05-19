package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "os"
    v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
)

func main() {
    flag.Parse()
    if len(flag.Args()) != 1 {
        fmt.Fprintln(os.Stderr, "Usage: copa-wiz <report-file>")
        os.Exit(1)
    }
    reportFile := flag.Arg(0)
    manifest, err := parseWizReport(reportFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error parsing report: %v\n", err)
        os.Exit(1)
    }
    if err := json.NewEncoder(os.Stdout).Encode(manifest); err != nil {
        fmt.Fprintf(os.Stderr, "Error encoding manifest: %v\n", err)
        os.Exit(1)
    }
}

func parseWizReport(filePath string) (*v1alpha1.UpdateManifest, error) {
    data, err := os.ReadFile(filePath)
    if err != nil {
        return nil, err
    }
    type wizReport struct {
        OS struct {
            Name    string `json:"name"`
            Version string `json:"version"`
        } `json:"os"`
        Vulnerabilities []struct {
            PackageName      string `json:"packageName"`
            InstalledVersion string `json:"installedVersion"`
            FixedVersion     string `json:"fixedVersion"`
            CVEID            string `json:"cveId"`
        } `json:"vulnerabilities"`
    }
    var report wizReport
    if err := json.Unmarshal(data, &report); err != nil {
        return nil, err
    }
    manifest := &v1alpha1.UpdateManifest{
        APIVersion: "v1alpha1",
        Metadata: v1alpha1.Metadata{
            OS: v1alpha1.OS{
                Type:    report.OS.Name,
                Version: report.OS.Version,
            },
            Config: v1alpha1.Config{
                Arch: "amd64",
            },
        },
        Updates: make([]v1alpha1.UpdatePackage, len(report.Vulnerabilities)),
    }
    for i, vuln := range report.Vulnerabilities {
        manifest.Updates[i] = v1alpha1.UpdatePackage{
            Name:             vuln.PackageName,
            InstalledVersion: vuln.InstalledVersion,
            FixedVersion:     vuln.FixedVersion,
            VulnerabilityID:  vuln.CVEID,
        }
    }
    return manifest, nil
}
