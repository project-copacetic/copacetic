---
title: Release Process
---

## Overview

The release process for Copacetic uses [GoReleaser](https://goreleaser.com/). 

Once you are ready to cut a new release, checkout the release branch and tag it with the respective version.

	```
	git checkout <BRANCH NAME>
	git pull origin <BRANCH NAME>
	git tag -a <NEW VERSION> -m '<NEW VERSION>'
	git push origin <NEW VERSION>
	```

## Publishing

1. GoReleaser will create a new release, review and edit it at https://github.com/project-copacetic/copacetic/releases
2. Review the respective copa-action image at: https://github.com/orgs/project-copacetic/packages/container/package/copa-action
