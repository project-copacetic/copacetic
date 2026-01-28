#!/bin/bash
set -e

docker buildx rm copademo-python
docker rmi python:3.11.0-patched
docker rmi python:3.11.0
rm -f python-scan.json
