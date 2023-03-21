#!/bin/bash

########################
# include the magic
########################
. demo-magic.sh

# hide the evidence
clear

# Put your stuff here
pei "docker kill buildkitd"
pei "docker rmi nginx:1.21.6-patched"
pei "docker rmi nginx:1.21.6"
pei "rm nginx.1.21.6.json"
