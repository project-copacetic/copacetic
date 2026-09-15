# Demos

This directory contains demo scripts that use [demo-magic](https://github.com/paxtonhare/demo-magic) to walk through Copa patching workflows.

## Prerequisites

- [Copa](https://github.com/project-copacetic/copacetic) installed
- Docker with buildx
- [Trivy](https://aquasecurity.github.io/trivy/) scanner

## Available Demos

| Script | Description |
|--------|-------------|
| `copa-demo.sh` | OS-level patching of `nginx:1.21.6` |
| `copa-demo-dotnet.sh` | OS + .NET library patching of [Azure Relay Bridge](https://github.com/Azure/azure-relay-bridge) |
| `copa-demo-nodejs.sh` | OS + Node.js library patching of `node:18-alpine` |
| `copa-demo-python.sh` | OS + Python library patching of `python:3.11-alpine` |

## Running a Demo

```bash
cd demo
bash copa-demo.sh
```

The language patching demos require the `COPA_EXPERIMENTAL=1` environment variable, which is set automatically within each script.

## Cleanup

Each demo has a matching cleanup script that removes the buildx instance, patched/original images, and scan output:

| Demo | Cleanup |
|------|---------|
| `copa-demo.sh` | `copa-demo-cleanup.sh` |
| `copa-demo-dotnet.sh` | `copa-demo-dotnet-cleanup.sh` |
| `copa-demo-nodejs.sh` | `copa-demo-nodejs-cleanup.sh` |
| `copa-demo-python.sh` | `copa-demo-python-cleanup.sh` |

```bash
bash copa-demo-python-cleanup.sh
```

