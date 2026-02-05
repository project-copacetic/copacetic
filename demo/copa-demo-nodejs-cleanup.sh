#!/bin/bash

docker buildx rm copademo-nodejs
docker rmi ghost:latest-patched
docker rmi ghost:latest
rm -f nodejs-scan.json
