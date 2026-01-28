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
pei "trivy image --scanners vuln --pkg-types library --ignore-unfixed -q python:3.11.0 2>&1 | grep Total"

p "# Step 2: Export scan results to JSON"
pei "trivy image --scanners vuln --pkg-types os,library --ignore-unfixed -q -f json -o python-scan.json python:3.11.0"

p "# Step 3: Create a BuildKit instance"
pei "docker buildx create --name copademo-python"

p "# Step 4: Patch the image with Copa"
pei "COPA_EXPERIMENTAL=1 copa patch -i python:3.11.0 -r python-scan.json -t 3.11.0-patched -a buildx://copademo-python --pkg-types os,library --library-patch-level major --ignore-errors"

p "# Step 5: Verify the patched image"
pei "trivy image --scanners vuln --pkg-types library --ignore-unfixed -q python:3.11.0-patched 2>&1 | grep Total"

p "# Learn more about Copa at - https://github.com/project-copacetic/copacetic"
