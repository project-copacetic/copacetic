# Test Node.js Application

This directory contains a vulnerable Node.js application used for testing Copa's Node.js vulnerability patching capabilities.

## Vulnerable Dependencies

The application includes these intentionally vulnerable packages:
- `ansi-regex@3.0.0` - CVE-2021-3807 (ReDoS vulnerability)
- `lodash@4.17.20` - CVE-2021-23337, CVE-2020-28500 (Command injection, ReDoS)
- `minimist@1.2.5` - CVE-2021-44906 (Prototype pollution)
- `node-fetch@2.6.0` - CVE-2022-0235, CVE-2020-15168 (Information exposure, DoS)

## Usage

This app is built by the GitHub Actions workflow and scanned with Trivy to generate vulnerability reports for testing Copa's Node.js patching functionality.

The workflow:
1. Builds this Docker image as `vulnerable-node-app:latest`
2. Scans it with Trivy to generate a vulnerability report
3. Uses Copa to patch the vulnerabilities
4. Verifies that the vulnerabilities were successfully fixed