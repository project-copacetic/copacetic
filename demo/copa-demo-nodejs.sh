#!/bin/bash

########################
# include the magic
########################
. demo-magic.sh

NO_WAIT=true
DEMO_COMMENT_COLOR=$CYAN

# hide the evidence
clear

p "# Step 1: Scan the image for vulnerabilities"
pei "trivy image --scanners vuln --pkg-types library --ignore-unfixed -q node:18-alpine 2>&1 | grep 'Total:'"

p "# Step 2: Export scan results to JSON"
pei "trivy image --scanners vuln --pkg-types os,library --ignore-unfixed -q -f json -o nodejs-scan.json node:18-alpine"

p "# Step 3: Create a BuildKit instance"
pei "docker buildx create --name copademo-nodejs"

p "# Step 4: Patch the image with Copa"
pei "COPA_EXPERIMENTAL=1 copa patch -i node:18-alpine -r nodejs-scan.json -t 18-alpine-patched -a buildx://copademo-nodejs --pkg-types os,library --library-patch-level major --ignore-errors --timeout 20m"

p "# Step 5: Verify the patched image"
pei "trivy image --scanners vuln --pkg-types library --ignore-unfixed -q node:18-alpine-patched 2>&1 | grep 'Total:'"

p "# Learn more about Copa at - https://github.com/project-copacetic/copacetic"
