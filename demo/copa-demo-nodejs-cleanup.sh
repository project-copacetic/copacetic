#!/bin/bash

docker buildx rm copademo-nodejs
docker rmi node:18-alpine-patched
docker rmi node:18-alpine
rm -f nodejs-scan.json
