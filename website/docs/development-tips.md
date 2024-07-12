# Development and Testing Tips

This document provides some tips and tricks for devs to better understand what is happening under the hood of `copa`.

Much of the functionality of `copa` is implemented through the use of the [BuildKit](https://docs.docker.com/build/buildkit/) library, and in particular, direct building a [Low-Level Build (LLB)](https://github.com/moby/buildkit#exploring-llb) intermediate representation. Most patching operations are implemented as a series of LLB stages that form a Directed Acyclic Graph (DAG) to produce the final patched image, and we'll walk through some ways to deal with the opaque nature of each operation in that graph which can otherwise make it difficult to debug or test `copa`.

## Use the `--debug` flag with `copa patch`

It's always useful to know that code on the `copa` side is behaving as expected first before diving into the weeds of its interactions with BuildKit. The `--debug` flag will do two useful things when enabled:

- Log debug state to stdout with the `DEBU` tag, including useful information such as the type of image it expects to be operating on, the list of updates and their versions it expects to apply, and any detailed errors.
- Leave the working folder in place so that you can inspect the contents of the working files `copa` writes for its own use during the patching process.

For example, if you run `copa patch` with the `--debug` flag, you'll see something like the following output:

```bash
$ copa patch -i <image> -r <report> --debug
DEBU[0000] updates to apply: ...
...
WARN[0000] --debug specified, working folder at /var/folders/fx/nbhd5jln1qq3t405hz_hl4000000gn/T/copa-806164554 needs to be manually cleaned up 
```

The folder specified defaults to the system temp folder unless the `--working-folder` option was specified, and you can delete it with `rm -r <folder>` when you're done. The working folder will usually contain the `copa-out` directory which contains files depending on the `pkgmgr` implementation, such as the probed package state or post-patching package state file for the package manager. Searching for `SolveToLocal()` invocations in the `copa` codebase will show you where these files are written.

## Verify the intermediate stages of building a patched image

It's often useful to be able to inspect what the output of an intermediate LLB stage would look like after it has executed, and you can perform an analog to `printf` debugging by solving the LLB stage to a Docker image and then inspecting the resulting image:

```go
// Add this to pkg/buildkit/buildkit.go to use
func SolveToDocker(ctx context.Context, c *client.Client, st *llb.State, configData []byte, tag string) error {
	def, err := st.Marshal(ctx)
	if err != nil {
		log.Errorf("st.Marshal failed with %s", err)
		return err
```

```go
// DEBUG: Solve the LLB stage to a Docker image.
if err := buildkit.SolveToDocker(ctx, dm.config.Client, &<llb.Stage>, dm.config.ConfigData, dm.config.ImageName+"-<llb.Stage suffix>"); err != nil {
    return nil, err
}
```

For example, if you want to see what the resulting Docker image looks like at the `busyBoxApplied` stage, you can add the `buildkit.SolveToDocker` call to the end of the `busyBoxApplied` stage as follows. The result will be a Docker image with the `-busyBoxApplied` suffix to the tag that you can inspect with the `docker` CLI or `dive` tool:

```go
busyBoxApplied := dm.config.ImageState.File(llb.Copy(toolImage, "/bin/busybox", "/bin/busybox"))
if err := buildkit.SolveToDocker(ctx, dm.config.Client, &busyBoxApplied, dm.config.ConfigData, dm.config.ImageName+"-busyBoxApplied"); err != nil {
    return nil, err
}
```

## Inspect a Docker image

### Use `docker` to inspect the metadata of the image

For a quick check of a Docker image, the built in `docker` CLI commands can be useful:

- [`docker inspect`](https://docs.docker.com/engine/reference/commandline/inspect/) can show you the metadata for the image and verifying that the patching process generally preserves the metadata of the original image.
- [`docker history`](https://docs.docker.com/engine/reference/commandline/history/) can give you a quick overview of the layers in the image, and with the `--no-trunc` flag, can provide the commands that were run to create each layer.

### Use `dive` to inspect the filesystem differences at each layer of the image

Instructions for installing and using the `dive` CLI tool are at https://github.com/wagoodman/dive.

`dive` provides a simple interface for walking the layers of the image and inspecting the files that were added or changed at each layer with your arrow keys.

- `Tab` will toggle between navigating the layers and the files in the layer.
- Filtering out unmodified files with `Ctrl+U` while in files view will effectively show you the file diff introduced by that layer.

In particular, if you are adding or changing any of the patching functionality, the diff view of the files in the image can be useful to verify that the expected files have actually been written to the target image.
### Extract individual files from the image to inspect them

`dive` won't let you read the contents of the files in the image though; to do that, you can use the `docker cp` command to copy the files out of the image to a local folder. Note that `docker cp` only works with containers and not just container images, so you will need to create a container from the image and then copy the files out of the container:

```bash
id=$(docker create <image name>:<tag>)
docker cp $id:<filepath> <destination path>
docker rm -v $id
```

### Use `crane` to manipulate the image or extract the image filesystem

Sometimes it's useful to be able to manipulate the image in ways that `docker` or `dive` don't support, such as extracting the entire image filesystem to a local folder. [`crane`](https://github.com/google/go-containerregistry/tree/main/cmd/crane) can be useful for this and also provides [many other convenient utilities](https://github.com/google/go-containerregistry/blob/main/cmd/crane/doc/crane.md) for working with container images.

For instance, to extract the filesystem of the image to a local folder, you can use `crane export`:

```bash
crane export <image name>:<tag> - | tar -xvf -
```

`crane` is a very flexible tool designed to work well with pipes to existing shell tools. For example, you can also use `crane` to do a full diff between two images as well:

```bash
 diff \
    <(crane export image:tag - | tar -tvf - | sort) \
    <(crane export image:tag-patched - | tar -tvf - | sort)
```

## Run scripts interactively in an image

Some of the LLB stages effectively run shell scripts defined by `copa` in the image, and sometimes these need to be debugged or modified. The easiest way to do this is usually just solving the `llb.Stage` of interest to Docker and then running the image interactively with `docker run`:

```bash
docker run --rm -it --entrypoint sh <image name>:<tag>-<llb.Stage suffix>
```

One thing to note is that the scripts embedded in the `.go` files will often have an additional layer of character escapes to make them valid Go strings, so you may need to unescape them before running them interactively.

## Dump the LLB Graph

Ultimately, `copa` is just a tool for building a BuildKit LLB graph, and you may need to understand if the LLB graph being constructed is reasonable or expected. It's helpful to have a basic understanding of how BuildKit and the operations commonly used by `copa` here, so it's good to be familiar with some key resources here:

- [BuildKit pkg.go.dev README](https://pkg.go.dev/github.com/moby/buildkit#section-readme)
- [BuildKit Developer Docs](https://github.com/moby/buildkit/tree/master/docs/dev)
- [Merge+Diff: Building DAGs More Efficiently and Elegantly](https://www.docker.com/blog/mergediff-building-dags-more-efficiently-and-elegantly/)

The LLB graph up to any `llb.Stage` can be written out by marshalling it to a `Definition` and enumerating each of the operations to output. Using the `buildctl` implementation of [dumpLLB](https://github.com/moby/buildkit/blob/master/cmd/buildctl/debug/dumpllb.go#L30) as a reference, you can write a function to output the LLB graph as JSON nodes to stdout:

```go
import "github.com/moby/buildkit/solver/pb"

// Definition of the LLB graph node to display, modify as desired.
// This version is what the buildctl tool uses.
type llbOp struct {
    Op         pb.Op
    Digest     digest.Digest
    OpMetadata pb.OpMetadata
}

func outputLLBGraph(ctx context.Context, llbState *llb.State) error {
    // Marshal the llb.State to a LLB definition.
    def, err := llbState.Marshal(ctx)
    if err != nil {
        log.Errorf("Marshal to LLB failed with %s", err)
        return err
    }

    // Format each operation node in the LLB definition into a struct.
    var ops []llbOp
    for _, dt := range def.Def {
        var op pb.Op
        if err := (&op).Unmarshal(dt); err != nil {
            return errors.Wrap(err, "failed to parse op")
        }
        hash := digest.FromBytes(dt)
        ent := llbOp{Op: op, Digest: hash, OpMetadata: def.Metadata[hash]}
        ops = append(ops, ent)
    }

    // Output the LLB graph as JSON nodes to stdout.
    // Modify as desired to output to file or other formats.
    enc := json.NewEncoder(os.Stdout)
    for _, op := range ops {
        if err := enc.Encode(op); err != nil {
            return err
        }
    }
    return nil
}

// Within the function (e.g. with the llb.State where you want to dump the LLB graph:
...
    // DEBUG: dump the LLB graph to stdout
    if err := outputLLBGraph(ctx, &merged); err != nil {
        return nil, err
    }
...
```

For the definition of an LLB vertex (an `Op` node struct enumerated by the code snippet above), refer to https://github.com/moby/buildkit/blob/master/solver/pb/ops.proto. 

Following the edges between the LLB nodes is a matter of following the resulting `Digest` value for the node to where it is consumed as one of the `Op.inputs` in another node. For example, a pretty-printed version of a LLB graph in json format focusing on a few key nodes might look like:

```json
// Initial target image source node
{
    "Op": {
        "Op": {
            "source": {
                "identifier": "docker-image://mcr.microsoft.com/oss/open-policy-agent/opa:0.46.0"
            }
        },
        "platform": {
            "Architecture": "amd64",
            "OS": "linux"
        },
        "constraints": {}
    },
    "Digest": "sha256:a86ddb9065d07c67dc838e11a81ff54020531c4ca2d85fb20574088222da8b30",
    "OpMetadata": {
        "caps": {
            "source.image": true
        }
    }
}

// ..
// Skipping intermediate graph nodes
// ...

// Diffing out the manifest updates layer
{
    "Op": {
        "inputs": [
            {
                "digest": "sha256:cbc31a96266caa8cd5ced38a1f8e97de9f13fafb23dbe9e342125569cd4d5018",
                "index": 0
            },
            {
                "digest": "sha256:9f798b2e38e054aadf1ee66c7eb7230c65be324c26d8739a3d5fa2d5da90e5de",
                "index": 0
            }
        ],
        "Op": {
            "diff": {
                "lower": {
                    "input": 0
                },
                "upper": {
                    "input": 1
                }
            }
        },
        "constraints": {}
    },
    "Digest": "sha256:f337f99144ab75fee8593ec6531caa9ebace06aaca07614778b7c0ca5c816135",
    "OpMetadata": {
        "caps": {
            "diffop": true
        }
    }
}

// Merging all the target image with the patch layer and the manifest updates layer
{
    "Op": {
        "inputs": [
            {
                "digest": "sha256:a86ddb9065d07c67dc838e11a81ff54020531c4ca2d85fb20574088222da8b30",
                "index": 0
            },
            {
                "digest": "sha256:1c3ad84c0de7e1384d727f6168db3f1f8fb632c0086760aff1786a7e89562d13",
                "index": 0
            },
            {
                "digest": "sha256:f337f99144ab75fee8593ec6531caa9ebace06aaca07614778b7c0ca5c816135",
                "index": 0
            }
        ],
        "Op": {
            "merge": {
                "inputs": [
                    {
                        "input": 0
                    },
                    {
                        "input": 1
                    },
                    {
                        "input": 2
                    }
                ]
            }
        },
        "constraints": {}
    },
    "Digest": "sha256:e6a4086e2caf03c8814fc5388dd7d2e45420e1c5281e0df0d3db375d3f00358a",
    "OpMetadata": {
        "caps": {
            "mergeop": true
        }
    }
}

//...

```
