#!/bin/bash

########################
# include the magic
########################
. demo-magic.sh

NO_WAIT=true
DEMO_COMMENT_COLOR=$CYAN

# hide the evidence
clear

p "# Step 0: Build a .NET image locally from Azure Relay Bridge"
pei "rm -rf /tmp/azure-relay-bridge && git clone --depth 1 https://github.com/Azure/azure-relay-bridge.git /tmp/azure-relay-bridge"
pei "docker build -t azure-relay-bridge:local /tmp/azure-relay-bridge"

p "# Step 1: Scan the image for vulnerabilities"
pei "trivy image --scanners vuln --pkg-types library --ignore-unfixed -q azure-relay-bridge:local"

p "# Step 2: Export scan results to JSON"
pei "trivy image --scanners vuln --pkg-types os,library --ignore-unfixed -q -f json -o dotnet-scan.json azure-relay-bridge:local"

p "# Step 3: Patch the image with Copa (using docker:// for local images)"
pei "COPA_EXPERIMENTAL=1 copa patch -i azure-relay-bridge:local -r dotnet-scan.json -t local-patched -a docker:// --pkg-types os,library --library-patch-level major --ignore-errors --timeout 30m"

p "# Step 4: Verify the patched image"
pei "trivy image --scanners vuln --pkg-types library --ignore-unfixed -q azure-relay-bridge:local-patched"

p "# Learn more about Copa at - https://github.com/project-copacetic/copacetic"
