#!/bin/bash

docker buildx rm copademo
docker rmi nginx:1.21.6-patched
docker rmi nginx:1.21.6
rm -f nginx.1.21.6.json
