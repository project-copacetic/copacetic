# Visual Studio Code Development Container

[VSCode](https://code.visualstudio.com/) supports development in a containerized environment through its [Remote - Container extension](https://code.visualstudio.com/docs/remote/containers). This folder provides a development container which encapsulates the dependencies specified in the [instructions to build and run copa](../docs/tutorials/dev-setup.md).

## Prerequisites

1. [Docker](https://docs.docker.com/get-docker/)
   > For Windows users, enabling [WSL2 back-end integration with Docker](https://docs.docker.com/docker-for-windows/wsl/) is recommended.
2. [Visual Studio Code](https://code.visualstudio.com/)
3. [Visual Studio Code Remote - Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

## Using the dev container

1. After you have cloned this repo locally, open the repo folder in VSCode. VSCode will detect the presence of this `.devcontainer` subfolder and will prompt you to reopen the project in a container.

   Alternatively, you can open the command palette and use the `Remote-Containers: Reopen in Container` command.

2. Once the container is loaded, open an [integrated terminal](https://code.visualstudio.com/docs/editor/integrated-terminal) in VSCode and you can start running the demo instructions.

> **⚠ If running via Docker Desktop for Windows**
>
> Note that the [mounted workspace files appear owned by `root`](https://code.visualstudio.com/remote/advancedcontainers/add-nonroot-user) in the dev container, which will cause `git` commands to fail with a `fatal: detected dubious ownership in a repository` error due to [safe.directory](https://git-scm.com/docs/git-config/2.35.2#Documentation/git-config.txt-safedirectory) checks. This can be addressed by changing the mapped ownership of the workspace files in the dev container to the `vscode` user:
>
> ```bash
> sudo chown -R vscode:vscode /workspace/copacetic
> ```

### Personalizing user settings in a dev container

VSCode supports applying your user settings, such as your `.gitconfig`, to a dev container through the use of [dotfiles repositories](https://code.visualstudio.com/docs/remote/containers#_personalizing-with-dotfile-repositories). This can be done through your own VSCode `settings.json` file without changing the dev container image or configuration.
