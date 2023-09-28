# Copa Github Action

## Overview

The [Copa Github Action](https://github.com/project-copacetic/copa-action) allows you patch vulnerable containers in your workflows using Copa. 
See Copa Action docs for example usage.

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
