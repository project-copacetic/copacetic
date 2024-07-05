---
title: Quick Start
---

This guide illustrates how to patch outdated containers with `copa`.

## Prerequisites

* Linux or macOS configured through the [setup instructions](./installation.md). This includes:
  * `copa` tool [built & pathed](./installation.md).
  * [buildkit](https://github.com/moby/buildkit/#quick-start) daemon installed & pathed. [Examples](#buildkit-connection-examples)
    * The `docker` daemon runs a buildkit service in-process. If you are using this for your buildkit instance, Docker must have the [containerd image store feature](https://docs.docker.com/storage/containerd/) enabled.
    * If you are using a buildx instance, or using buildkitd directly, there is no need to enable the containerd image store. However, only images in a remote registry can be patched using these methods.
  * [docker](https://docs.docker.com/desktop/linux/install/#generic-installation-steps) daemon running and CLI installed & pathed.
  * Optional:
    * [trivy CLI](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) installed & pathed.  
      * Alternatively, see [scanner plugins](#scanner-plugins) for custom scanner support.

## Sample Steps

1. Before patching your image, specify a buildkit instance to connect to:

    By default copa will attempt to auto-connect to an instance in order:
      1. Default docker buildkit endpoint (requires at least docker v24.0 with [containerd image store](https://docs.docker.com/storage/containerd/#enable-containerd-image-store-on-docker-engine) support enabled)
      2. Currently selected buildx builder (see: `docker buildx --help`)
      3. buildkit daemon at the default address `/run/buildkit/buildkitd.sock`

    If an instance doesn't exist or that instance doesn't support all the features copa needs the next will be attempted. Please see [custom buildkit addresses](custom-address.md) for more information.

2.  Scan the container image to check for patchable OS vulnerabilities:
    ```bash
    $ export IMAGE=docker.io/library/nginx:1.21.6
    $ trivy image --vuln-type os --ignore-unfixed $IMAGE
    nginx:1.21.6 (debian 11.3)
    ==========================
    Total: 207 (UNKNOWN: 0, LOW: 12, MEDIUM: 104, HIGH: 76, CRITICAL: 15)
    ...
    ```

3. Patch the supplied image with Copa:

    1. Update all outdated packages
        By default, Copa will update all outdated packages in an image to the latest available versions. 
        :::note
        Upgrading all packages may introduce compatibility issues or break existing functionality. Make sure to test the patched image to ensure stability. 
        :::

        ```bash
        copa patch -i $IMAGE
        ```

        :::tip 
        If you want to patch an image using the digest, run the following command instead: 
        
        ```bash
            export IMAGE=docker.io/library/nginx:1.21.6@sha256:25dedae0aceb6b4fe5837a0acbacc6580453717f126a095aa05a3c6fcea14dd4
            copa patch -i $IMAGE
        ```
        :::

    2. Update only targeted packages
        Alternatively, you can chose to have a targeted patching of your image by providing an optional vulnerability report. In the following commands, we are only updating packages marked vulnerable by Trivy:

        2.1. Scan the container image for patchable OS vulnerabilities, outputting the results to a JSON file:
        ```bash
        trivy image --vuln-type os --ignore-unfixed -f json -o $(basename $IMAGE).json $IMAGE
        ```
        
        2.2. Supply the Trivy report as an additional argument to the Copa command to patch image.

        ```bash
        copa patch -r $(basename $IMAGE).json -i $IMAGE
        ```
    
    In both cases by default, Copa will produce a tag with a `-patched` suffix and export a new image with the specified `1.21.6-patched` label to the local Docker daemon. 

    :::note
    If you're running this sample against an image from a private registry instead,ensure that the credentials are configured in the default Docker config.json before running `copa patch`, for example, via `docker login -u <user> -p <password> <registry>`.
    :::

    :::note
    If you're patching an image that is local-only (i.e. built or tagged locally but not pushed to a registry), `copa` is limited to using `docker`'s built-in buildkit service, and must use the [`containerd image store`](https://docs.docker.com/storage/containerd/) feature. This is because only `docker`'s built-in buildkit service has access to the docker image store (see [Prerequisites](#prerequisites) for more information.)
    :::
    
4. Scan the patched image again and verify that the vulnerabilities have been patched:

    ```bash
    $ trivy image --vuln-type os --ignore-unfixed $IMAGE-patched
    nginx:1.21.6-patched (debian 11.10)
    ===================================
    Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)
    ```
    
5. Run the container to verify that the image has no regressions:

    ```bash
    $ docker run -it --rm --name test $IMAGE-patched
    /docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform configuration
    /docker-entrypoint.sh: Looking for shell scripts in /docker-entrypoint.d/
    /docker-entrypoint.sh: Launching /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh
    10-listen-on-ipv6-by-default.sh: info: Getting the checksum of /etc/nginx/conf.d/default.conf
    10-listen-on-ipv6-by-default.sh: info: Enabled listen on IPv6 in /etc/nginx/conf.d/default.conf
    /docker-entrypoint.sh: Launching /docker-entrypoint.d/20-envsubst-on-templates.sh
    /docker-entrypoint.sh: Launching /docker-entrypoint.d/30-tune-worker-processes.sh
    /docker-entrypoint.sh: Configuration complete; ready for start up
    2024/01/22 23:32:54 [notice] 1#1: using the "epoll" event method
    2024/01/22 23:32:54 [notice] 1#1: nginx/1.21.6
    2024/01/22 23:32:54 [notice] 1#1: built by gcc 10.2.1 20210110 (Debian 10.2.1-6)
    2024/01/22 23:32:54 [notice] 1#1: OS: Linux 6.2.0-1018-azure
    2024/01/22 23:32:54 [notice] 1#1: getrlimit(RLIMIT_NOFILE): 1048576:1048576
    2024/01/22 23:32:54 [notice] 1#1: start worker processes
    ```
   You can stop the container by opening a new shell instance and running: `docker stop test`

6. You can inspect the structure of the patched image with `docker history` to see the new patch layer appended to the image:

    ```bash
    $ docker history $IMAGE-patched
    IMAGE          CREATED              CREATED BY                                      SIZE      COMMENT
    262dacfeb193   About a minute ago   mount / from exec sh -c apt install --no-ins…   41.1MB    buildkit.exporter.image.v0
    <missing>      20 months ago        /bin/sh -c #(nop)  CMD ["nginx" "-g" "daemon…   0B
    <missing>      20 months ago        /bin/sh -c #(nop)  STOPSIGNAL SIGQUIT           0B
    <missing>      20 months ago        /bin/sh -c #(nop)  EXPOSE 80                    0B
    <missing>      20 months ago        /bin/sh -c #(nop)  ENTRYPOINT ["/docker-entr…   0B
    <missing>      20 months ago        /bin/sh -c #(nop) COPY file:09a214a3e07c919a…   16.4kB
    <missing>      20 months ago        /bin/sh -c #(nop) COPY file:0fd5fca330dcd6a7…   12.3kB
    <missing>      20 months ago        /bin/sh -c #(nop) COPY file:0b866ff3fc1ef5b0…   12.3kB
    <missing>      20 months ago        /bin/sh -c #(nop) COPY file:65504f71f5855ca0…   8.19kB
    <missing>      20 months ago        /bin/sh -c set -x     && addgroup --system -…   64.5MB
    <missing>      20 months ago        /bin/sh -c #(nop)  ENV PKG_RELEASE=1~bullseye   0B
    <missing>      20 months ago        /bin/sh -c #(nop)  ENV NJS_VERSION=0.7.3        0B
    <missing>      20 months ago        /bin/sh -c #(nop)  ENV NGINX_VERSION=1.21.6     0B
    <missing>      20 months ago        /bin/sh -c #(nop)  LABEL maintainer=NGINX Do…   0B
    <missing>      20 months ago        /bin/sh -c #(nop)  CMD ["bash"]                 0B
    <missing>      20 months ago        /bin/sh -c #(nop) ADD file:134f25aec8adf83cb…   91.8MB
    ```
