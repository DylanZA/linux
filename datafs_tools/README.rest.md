# OpenAPI REST provider

`datafs_rest.bpf.c` exposes OpenAPI 3 GET operations through datafs. The Rust
loader reads an OpenAPI JSON document and starts a loopback dispatch service.
Directory metadata and schemas are served on demand by that service, while
ordinary reads are proxied to the configured REST endpoint. OpenAPI parsing
remains outside the kernel and BPF program; filesystem HTTP framing and
response parsing remain in BPF.

The dispatch service is selected through the userspace `FilesystemDispatch`
interface. Only the REST loader instantiates `RestDispatch`; the S3, NFS, and
SMB loaders retain their direct protocol paths and do not pass through REST
code.

The loader probes the configured server for an OpenAPI document. It reports
each attempted location and accepts the first valid document found at:

```text
<base>/openapi.json
<base>/swagger.json
/openapi.json
/openapi.yaml
/swagger.json
/api/openapi.json
/v3/api-docs
```

Build and mount it with:

```sh
make -C datafs_tools
./datafs_tools/datafs_rest_loader \
  --mount /mnt/rest --server 192.0.2.10:80 --arg /v1
```

The mount argument is the server-side base path without a trailing slash. For
an OAS path `/api/foo`, these commands issue GET requests for the same endpoint;
the query string is deliberately absent from the directory entry but retained
when the file is opened:

```sh
ls /mnt/rest/api
cat '/mnt/rest/api/foo?a=1&b=2'
cat /mnt/rest/.schema/api/foo
```

The schema file contains the complete JSON GET operation object from the OAS
document. There is no BPF-map node or schema-size limit; schema ranges are read
from userspace only when requested. A single directory listing remains limited
to the shared 4096-byte BPF protocol payload. The loader accepts JSON OAS
documents and exposes only GET operations. REST endpoints must implement HEAD
with `Content-Length` and GET with byte ranges; an initial offset-zero GET may
return `200 OK`, while later reads require `206 Partial Content`.

## Arithmetic example

`datafs_rest_example.py` is a dependency-free example service providing add,
subtract, multiply, divide, modulo, power, and greatest-common-divisor
operations. Start the service and mount its bundled OpenAPI document:

```sh
python3 datafs_tools/datafs_rest_example.py

./datafs_tools/datafs_rest_loader \
  --mount /mnt/arithmetic --server 127.0.0.1:8000 --arg /v1
```

The endpoints and their schemas then behave like ordinary files:

```sh
ls /mnt/arithmetic
cat '/mnt/arithmetic/add?a=40&b=2'
cat '/mnt/arithmetic/divide?a=22&b=7'
cat /mnt/arithmetic/.schema/add
```

Run the self-contained VM smoke test with:

```sh
./datafs_tools/run_datafs_smoke.sh datafs-rest
```
