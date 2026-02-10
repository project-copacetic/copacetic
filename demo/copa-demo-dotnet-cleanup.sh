#!/bin/bash

docker rmi azure-relay-bridge:local-patched
docker rmi azure-relay-bridge:local
rm -f dotnet-scan.json
rm -rf /tmp/azure-relay-bridge
