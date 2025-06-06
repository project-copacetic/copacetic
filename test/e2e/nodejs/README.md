# Node.js E2E Tests

This directory contains end-to-end tests for Copa's Node.js vulnerability patching functionality.

## Test Cases

### TestNodeJSPatching
Tests the core Node.js patching functionality using a vulnerable Node.js application image:
- **Image**: `vulnerable-node-app:latest` with vulnerable npm packages
- **Vulnerabilities**: 7 Node.js package vulnerabilities (ansi-regex, lodash, minimist, node-fetch)
- **Verifies**: 
  - Successful patching operation
  - Package versions updated to fixed versions
  - Vulnerability count reduction

### TestNodeJSPatchingEdgeCases
Tests edge cases and error conditions:
- **Images without Node.js**: Ensures Copa gracefully handles non-Node.js images
- **Invalid reports**: Tests error handling for malformed vulnerability reports

## Test Data

### testdata/vulnerable-node-app-report.json
Trivy vulnerability report for the test image containing:
- CVE-2021-3807 (ansi-regex)
- CVE-2021-23337, CVE-2020-28500 (lodash) 
- CVE-2021-44906 (minimist)
- CVE-2022-0235, CVE-2020-15168 (node-fetch)
- CVE-2024-21538 (cross-spawn in npm)

## Running Tests

```bash
# Run locally with Copa binary
go test -v ./test/e2e/nodejs --addr="docker://" --copa="$(pwd)/copa" --scanner=trivy -timeout 0

# Run with custom buildkit address
go test -v ./test/e2e/nodejs --addr="tcp://localhost:1234" --copa="./copa" --scanner=trivy
```

## Test Image

The tests expect a `vulnerable-node-app:latest` image to exist. In CI, this is built automatically. For local testing, build the image using:

```bash
mkdir test-app && cd test-app
cat > package.json << 'EOF'
{
  "name": "vulnerable-node-app",
  "version": "1.0.0", 
  "dependencies": {
    "ansi-regex": "3.0.0",
    "lodash": "4.17.20",
    "minimist": "1.2.5", 
    "node-fetch": "2.6.0"
  }
}
EOF
echo 'console.log("Test app");' > index.js
cat > Dockerfile << 'EOF'
FROM node:18-alpine
RUN apk add --no-cache curl git
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
CMD ["node", "index.js"]
EOF
docker build -t vulnerable-node-app:latest .
```