# Remote bundle sync

K.O.D.A. evidence bundles are self-contained `.tar.gz` archives with a
Merkle chain baked in.  The remote sync feature lets operators push them to
any S3-compatible store (AWS S3, Cloudflare R2, MinIO) and pull them back
on another machine — without any background sync, telemetry, or phone-home.

---

## Configure

Create `~/.koda/remote.toml` (or the active profile's `KODA_HOME/remote.toml`):

```toml
bucket      = "my-evidence-bucket"
endpoint_url = "https://<accountid>.r2.cloudflarestorage.com"  # omit for AWS S3
region      = "us-east-1"
prefix      = "engagements/"   # optional key prefix
```

Credentials come from the standard AWS chain (`AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` env vars, `~/.aws/credentials`, or an IAM role).
They are never printed, logged, or included in audit events.

Config priority (highest → lowest):

1. CLI flags (`--bucket`, `--endpoint-url`, `--region`, `--prefix`)
2. Env vars: `KODA_REMOTE_BUCKET`, `KODA_REMOTE_ENDPOINT`, `KODA_REMOTE_REGION`,
   `KODA_REMOTE_PREFIX`
3. `KODA_HOME/remote.toml`

---

## AWS S3

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export KODA_REMOTE_BUCKET=my-bucket

koda remote push acme-pentest-2026
koda remote list
koda remote pull acme-pentest-2026_1714000000.tar.gz
```

---

## Cloudflare R2

R2 is S3-compatible but needs an endpoint URL:

```bash
export AWS_ACCESS_KEY_ID=<r2-access-key>
export AWS_SECRET_ACCESS_KEY=<r2-secret>
export KODA_REMOTE_BUCKET=my-r2-bucket
export KODA_REMOTE_ENDPOINT=https://<accountid>.r2.cloudflarestorage.com

koda remote push acme-pentest-2026
```

Or put it all in `remote.toml` so you don't have to type flags every time.

---

## MinIO (self-hosted)

```bash
koda remote push acme-pentest-2026 \
  --bucket koda-evidence \
  --endpoint-url http://minio.internal:9000 \
  --region us-east-1
```

---

## How integrity checking works

Every push writes **two** objects:

| Object | Content |
|--------|---------|
| `<prefix>/<key>.tar.gz` | The bundle |
| `<prefix>/<key>.tar.gz.sha256` | Plain-text SHA-256 hex digest, newline-terminated |

On pull, K.O.D.A. fetches the `.sha256` sidecar **first**, downloads the
bundle, recomputes the hash locally, and asserts they match before writing
a single byte to disk.  If the hashes disagree, no file is written and an
error is raised.

The sidecar is intentionally plain text (not JSON) so any operator can
verify a download from a shell:

```bash
curl -s https://.../acme-pentest.tar.gz | sha256sum
# compare against the .sha256 sidecar
```

---

## Concurrent pushes

Last-writer-wins (standard S3 `PUT` semantics).  If two operators push to
the same key simultaneously, the final object is whichever `PUT` completed
last — both the bundle and its sidecar will be consistent because K.O.D.A.
writes the sidecar after the bundle completes.  If you need immutable
versioning, enable bucket versioning at the provider level.

---

## boto3 dependency

`boto3` is optional and lazy-imported — it is only loaded when a `remote`
command actually runs.  Install it with:

```bash
pip install boto3
```
