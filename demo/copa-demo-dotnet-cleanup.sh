#!/bin/bash

docker buildx rm copademo-dotnet
docker rmi ashnam/dotnet-runtime-vuln:v2-patched
docker rmi ashnam/dotnet-runtime-vuln:v2
rm -f dotnet-scan.json
