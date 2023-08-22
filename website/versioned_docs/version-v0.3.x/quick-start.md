---
title: Quick Start
---

This sample illustrates how to patch containers using vulnerability reports with `copa`.

## Prerequisites

* An Ubuntu 22.04 VM configured through the [setup instructions](./installation.md) or a VSCode [devcontainer](./contributing.md/#visual-studio-code-development-container) environment. This includes:
  * `copa` tool [built & pathed](./installation.md).
  * [buildkit](https://github.com/moby/buildkit/#quick-start) daemon installed & pathed.
  * [docker](https://docs.docker.com/desktop/linux/install/#generic-installation-steps) daemon running and CLI installed & pathed.
  * [trivy CLI](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) installed & pathed.

## Sample Steps

1. Scan the container image for patchable OS vulnerabilities, outputting the results to a JSON file:

    ```bash
    trivy image --vuln-type os --ignore-unfixed -f json -o nginx.1.21.6.json docker.io/library/nginx:1.21.6
    ```

    You can also see the existing patchable vulnerabilities in table form on the shell with:

    ```bash
    trivy image --vuln-type os --ignore-unfixed docker.io/library/nginx:1.21.6

2. Patch the image using the Trivy report. You will need to start `buildkitd` if it is not already running:

    ```bash
    sudo buildkitd &
    sudo copa patch -i docker.io/library/nginx:1.21.6 -r nginx.1.21.6.json -t 1.21.6-patched
    ```

    Alternatively, you can run `buildkitd` in a container, which allows copa to be run without root access to the local buildkit socket:

    ```bash
    export BUILDKIT_VERSION=v0.11.4
    export BUILDKIT_PORT=8888
    docker run \
        --detach \
        --rm \
        --privileged \
        -p 127.0.0.1:$BUILDKIT_PORT:$BUILDKIT_PORT/tcp \
        --name buildkitd \
        --entrypoint buildkitd \
        "moby/buildkit:$BUILDKIT_VERSION" \
        --addr tcp://0.0.0.0:$BUILDKIT_PORT
    copa patch \
        -i docker.io/library/nginx:1.21.6 \
        -r nginx.1.21.6.json \
        -t 1.21.6-patched \
        -a tcp://0.0.0.0:$BUILDKIT_PORT
    ```

    In either case, `copa` is non-destructive and exports a new image with the specified `1.21.6-patched` label to the local Docker daemon.

    > **NOTE:** if you're running this sample against an image from a private registry instead,
    > ensure that the credentials are configured in the default Docker config.json before running `copa patch`,
    > for example, via `sudo docker login -u <user> -p <password> <registry>`.

3. Scan the patched image and verify that the vulnerabilities have been patched:

    ```bash
    trivy image --vuln-type os --ignore-unfixed docker.io/library/nginx:1.21.6-patched
    ```

    You can also inspect the structure of the patched image with `docker history` to see the new patch layer appended to the image:

    ```bash
    $ docker history docker.io/library/nginx:1.21.6-patched
    IMAGE          CREATED        CREATED BY                                      SIZE      COMMENT
    a372df41e06d   1 minute ago   mount / from exec sh -c apt install --no-ins…   26.1MB    buildkit.exporter.image.v0
    <missing>      3 months ago   CMD ["nginx" "-g" "daemon off;"]                0B        buildkit.dockerfile.v0
    <missing>      3 months ago   STOPSIGNAL SIGQUIT                              0B        buildkit.dockerfile.v0
    <missing>      3 months ago   EXPOSE map[80/tcp:{}]                           0B        buildkit.dockerfile.v0
    <missing>      3 months ago   ENTRYPOINT ["/docker-entrypoint.sh"]            0B        buildkit.dockerfile.v0
    <missing>      3 months ago   COPY 30-tune-worker-processes.sh /docker-ent…   4.61kB    buildkit.dockerfile.v0
    <missing>      3 months ago   COPY 20-envsubst-on-templates.sh /docker-ent…   1.04kB    buildkit.dockerfile.v0
    <missing>      3 months ago   COPY 10-listen-on-ipv6-by-default.sh /docker…   1.96kB    buildkit.dockerfile.v0
    <missing>      3 months ago   COPY docker-entrypoint.sh / # buildkit          1.2kB     buildkit.dockerfile.v0
    <missing>      3 months ago   RUN /bin/sh -c set -x     && addgroup --syst…   61.1MB    buildkit.dockerfile.v0
    <missing>      3 months ago   ENV PKG_RELEASE=1~bullseye                      0B        buildkit.dockerfile.v0
    <missing>      3 months ago   ENV NJS_VERSION=0.7.0                           0B        buildkit.dockerfile.v0
    <missing>      3 months ago   ENV NGINX_VERSION=1.20.2                        0B        buildkit.dockerfile.v0
    <missing>      3 months ago   LABEL maintainer=NGINX Docker Maintainers <d…   0B        buildkit.dockerfile.v0
    <missing>      4 months ago   /bin/sh -c #(nop)  CMD ["bash"]                 0B
    <missing>      4 months ago   /bin/sh -c #(nop) ADD file:09675d11695f65c55…   80.4MB
    ```

5. Run the container to verify that the image has no regressions:

    ```bash
    $ docker run -it --rm --name nginx-test docker.io/library/nginx:1.21.6-patched
    /docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform configuration
    /docker-entrypoint.sh: Looking for shell scripts in /docker-entrypoint.d/
    /docker-entrypoint.sh: Launching /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh
    10-listen-on-ipv6-by-default.sh: info: Getting the checksum of /etc/nginx/conf.d/default.conf
    10-listen-on-ipv6-by-default.sh: info: Enabled listen on IPv6 in /etc/nginx/conf.d/default.conf
    /docker-entrypoint.sh: Launching /docker-entrypoint.d/20-envsubst-on-templates.sh
    /docker-entrypoint.sh: Launching /docker-entrypoint.d/30-tune-worker-processes.sh
    /docker-entrypoint.sh: Configuration complete; ready for start up
    2022/05/16 18:00:17 [notice] 1#1: using the "epoll" event method
    2022/05/16 18:00:17 [notice] 1#1: nginx/1.20.2
    2022/05/16 18:00:17 [notice] 1#1: built by gcc 10.2.1 20210110 (Debian 10.2.1-6)
    2022/05/16 18:00:17 [notice] 1#1: OS: Linux 5.10.102.1-microsoft-standard-WSL2
    2022/05/16 18:00:17 [notice] 1#1: getrlimit(RLIMIT_NOFILE): 1048576:1048576
    2022/05/16 18:00:17 [notice] 1#1: start worker processes
    2022/05/16 18:00:17 [notice] 1#1: start worker process 31
    2022/05/16 18:00:17 [notice] 1#1: start worker process 32
    2022/05/16 18:00:17 [notice] 1#1: start worker process 33
    2022/05/16 18:00:17 [notice] 1#1: start worker process 34
    2022/05/16 18:00:17 [notice] 1#1: start worker process 35
    2022/05/16 18:00:17 [notice] 1#1: start worker process 36
    2022/05/16 18:00:17 [notice] 1#1: start worker process 37
    2022/05/16 18:00:17 [notice] 1#1: start worker process 38
    2022/05/16 18:00:17 [notice] 38#38: signal 28 (SIGWINCH) received
    2022/05/16 18:00:17 [notice] 36#36: signal 28 (SIGWINCH) received
    2022/05/16 18:00:17 [notice] 33#33: signal 28 (SIGWINCH) received
    2022/05/16 18:00:17 [notice] 32#32: signal 28 (SIGWINCH) received
    2022/05/16 18:00:17 [notice] 34#34: signal 28 (SIGWINCH) received
    2022/05/16 18:00:17 [notice] 35#35: signal 28 (SIGWINCH) received
    2022/05/16 18:00:17 [notice] 37#37: signal 28 (SIGWINCH) received
    2022/05/16 18:00:17 [notice] 1#1: signal 28 (SIGWINCH) received
    2022/05/16 18:00:17 [notice] 31#31: signal 28 (SIGWINCH) received
    ```

   You can stop the container by opening a new shell instance and running: `docker stop nginx-test`