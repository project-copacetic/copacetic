---
title: Copa Github Action
---

## Overview

The [Copa Github Action](https://github.com/project-copacetic/copa-action) allows you patch vulnerable containers in your workflows using Copa. 

## Inputs

## `image`

**Required** The image reference to patch.

## `image-report`

**Required** The trivy json vulnerability report of the image to patch.

## `patched-tag`

**Required** The new patched image tag.

## `buildkit-version`

**Optional** The buildkit version used in the action, default is latest.

## `copa-version`

**Optional** The Copa version used in the action, default is latest.

## Output

## `patched-image`

Image reference of the resulting patched image.

## Example Workflow

```
on: [push]

jobs:
    test:
        runs-on: ubuntu-latest

        strategy:
          fail-fast: false
          matrix:
            # provide relevant list of images to scan on each run
            images: ['docker.io/library/nginx:1.21.6', 'docker.io/openpolicyagent/opa:0.46.0', 'docker.io/library/hello-world:latest']

        steps:
        - name: Set up Docker Buildx
          uses: docker/setup-buildx-action@dedd61cf5d839122591f5027c89bf3ad27691d18

        - name: Generate Trivy Report
          uses: aquasecurity/trivy-action@69cbbc0cbbf6a2b0bab8dcf0e9f2d7ead08e87e4
          with:
            scan-type: 'image'
            format: 'json'
            output: 'report.json'
            ignore-unfixed: true
            vuln-type: 'os'
            image-ref: ${{ matrix.images }}

        - name: Check Vuln Count
          id: vuln_count
          run: |
            report_file="report.json"
            vuln_count=$(jq '.Results | length' "$report_file")
            echo "vuln_count=$vuln_count" >> $GITHUB_OUTPUT

        - name: Copa Action
          if: steps.vuln_count.outputs.vuln_count != '0'
          id: copa
          uses: project-copacetic/copa-action@v1
          with:
            image: ${{ matrix.images }}
            image-report: 'report.json'
            patched-tag: 'patched'
            buildkit-version: 'v0.11.6'
            # optional, default is latest
            copa-version: '0.4.1'

        - name: Login to Docker Hub
          if: steps.copa.conclusion == 'success'
          id: login
          uses: docker/login-action@b4bedf8053341df3b5a9f9e0f2cf4e79e27360c6
          with:
            username: 'user'
            password: ${{ secrets.DOCKERHUB_TOKEN }}

        - name: Docker Push Patched Image
          if: steps.login.conclusion == 'success'
          run: |
            docker push ${{ steps.copa.outputs.patched-image }}

```
