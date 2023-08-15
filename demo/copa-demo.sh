#!/bin/bash

########################
# include the magic
########################
. demo-magic.sh

# hide the evidence
clear

p "Use Trivy to output the number of vulnerabilities in the nginx:1.21.6 container image"
pei "trivy image --vuln-type os --ignore-unfixed nginx:1.21.6 | grep Total"

p "Use Trivy to scan the nginx:1.21.6 container image saving the output to nginx.1.21.6.json"
pei "trivy image --vuln-type os --ignore-unfixed -f json -o nginx.1.21.6.json nginx:1.21.6"

p "Create a buildkit instance to connect to"
pei "docker buildx create --name copademo"

p "List the buildkit instances"
pei "docker buildx ls"

p "Use copa to patch the nginx:1.21.6 container image outputting the patched container image to nginx:1.21.6-patched"
pei "copa patch -i docker.io/library/nginx:1.21.6 -r nginx.1.21.6.json -t 1.21.6-patched -a buildx://copademo"

p "Check that the nginx:1.21.6-patched container image is present locally"
pei "docker images | grep 1.21.6"

p "Use Trivy to scan the nginx:1.21.6-patched container image"
pei "trivy image --vuln-type os --ignore-unfixed nginx:1.21.6-patched | grep Total"

p "Verify that the patched container image runs"
pei "docker run nginx:1.21.6-patched"

p "Learn more about Copa at - https://github.com/project-copacetic/copacetic"
