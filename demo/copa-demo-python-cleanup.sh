#!/bin/bash

docker buildx rm copademo-python
docker rmi python:3.11-alpine-patched
docker rmi python:3.11-alpine
rm -f python-scan.json
