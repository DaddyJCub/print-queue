# Printables Source Ingest — Integration Notes

Lets an authenticated requester paste a Printables model link on the request
form, fetch the model's metadata and file list, multi-select files (with a
per-file quantity), and carry that selection into the submitted request.

- Provider module: [`app/integrations/printables_client.py`](../app/integrations/printables_client.py) (HTTP/GraphQL)
- Parser module: [`app/integrations/printables_parser.py`](../app/integrations/printables_parser.py) (URL + normalization, no network)
- Fetch endpoint: `POST /submit/fetch-provider-files` in [`app/public.py`](../app/public.py)
- Feature flag: `printables_fetch` (default **off** in production)
- Runtime mode env var: `PRINTABLES_FETCH_MODE`

## Provider contract (verified live)

Endpoint: `https://api.printables.com/graphql/` — public models need no auth.

### Metadata query

```graphql
query PrintQueueModel($id: ID!) {
  print(id: $id) {
    id name summary description filesCount excludeCommercialUsage premium price
    license { name abbreviation }
    user { publicUsername }
    stls { id name fileSize folder }
    gcodes { id name fileSize folder }
    slas { id name fileSize folder }
    otherFiles { id name fileSize folder fileFormat }
    downloadPacks { id name fileSize fileType }
  }
}
```

A missing model returns `{ "data": { "print": null } }` with HTTP 200.

### Direct download mutation (used only in `direct_import` mode)

```graphql
mutation PrintQueueDownload($printId: ID!, $source: DownloadSourceEnum!, $files: [DownloadFileInput]) {
  getDownloadLink(printId: $printId, source: $source, files: $files) {
    ok
    errors { field messages }
    output { link ttl count files { id link ttl fileType } }
  }
}
```

- `source` ∈ `model_detail | model_viewer`
- `DownloadFileInput = { fileType: DownloadFileTypeEnum!, ids: [ID]! }`
- `fileType` ∈ `stl | gcode | sla | other | pack`
- `output.files[].link` is a time-limited CDN URL (`ttl` ≈ 86400s) that
  downloads the binary unauthenticated.

## Normalized candidate JSON (PAT-001)

`normalize_file_candidates()` flattens the per-type lists into a deterministic
array. Each candidate:

```json
{
  "provider": "printables",
  "source_id": "258431",
  "file_id": "1207177",
  "file_type": "stl",
  "name": "Rugged Box - Box - 120x70x40.stl",
  "size_bytes": 196684,
  "folder": "Size 120 x 70 x 40 ...",
  "attachment_mode": "direct"
}
```

The fetch endpoint returns `{ "provider", "model", "candidates" }` where
`model` is `printables_parser.model_summary()`.

## Feasibility / attachment classification (TASK-004)

| Source on `print`            | `file_type` | `attachment_mode` | Behavior |
| ---------------------------- | ----------- | ----------------- | -------- |
| `stls`/`gcodes`/`slas`/`otherFiles` | individual | `direct` | Per-file direct download link available. |
| `downloadPacks`              | `pack`      | `package`         | Only a packaged (zip) download exists; attached as a reference/pack. |
| Premium or priced model      | any         | `reference-only`  | Binary not retrievable without purchase; metadata + link only. |

`supports_direct_asset_download(candidate)` returns `True` only for `direct`.

## Compliance decision matrix (TASK-005A, LEG-001/002)

`PRINTABLES_FETCH_MODE` controls how far the backend goes:

| Mode             | Metadata | File candidate list | Binary download / re-host |
| ---------------- | -------- | ------------------- | ------------------------- |
| `metadata_only`  | ✅ title/summary/description only | ❌ | ❌ |
| `reference_only` | ✅ | ✅ (selectable as references/links) | ❌ |
| `direct_import`  | ✅ | ✅ | ✅ `direct` candidates fetched server-side and stored as request files; `package`/`reference-only` stay references |

**Current default: `direct_import`** (operator-selected for this deployment).

> ⚠️ **Legal note (LEG-001/004).** `direct_import` performs automated binary
> retrieval. Confirm Printables' terms permit automated retrieval for
> user-initiated requests before enabling in production, and keep the
> `printables_fetch` flag scoped while doing so. Model rights and commercial
> permissions remain governed by the original creator's license — the license
> string and source attribution are persisted with each selected item
> (LEG-003) and surfaced to requesters/admins (LEG-004).

## Security posture

- Strict host allowlist `printables.com` / `www.printables.com` (SEC-001).
- Timeouts: 10s connect / 20s read; response-size ceiling (SEC-002).
- HTML description is sanitized before render/storage; a plain-text summary is
  stored for email/admin fallback (SEC-003).
- No remote provider JS executed server-side (SEC-004).
- Fetch endpoint is rate-limited per IP + requester (SEC-005) and requires an
  authenticated account (SEC-006 / TASK-007A).
