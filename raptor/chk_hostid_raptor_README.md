# chk_hostid_raptor.py

Finds Velociraptor offline-collector ZIPs that share the same `HostID` and
rewrites the duplicates with a new, unique `HostID` so they can be imported
into a Velociraptor server without colliding.

Duplicate HostIDs come from machines built from the same image or VM
template. Every clone carries the same identifier, so importing more than
one of them merges their results under a single client.

## Requirements

- Python 3.6 or newer
- Standard library only, no packages to install

## Usage

```
python3 chk_hostid_raptor.py -i <input-dir> -o <output-dir> [-r]
```

| Flag | Required | Meaning |
|------|----------|---------|
| `-i`, `--input-dir` | yes | Directory containing the collection ZIPs |
| `-o`, `--output-dir` | yes | Directory that receives the final ZIPs. Created if missing. A relative path is placed beside the input directory, not under the current directory |
| `-r`, `--rename-hostname` | no | Also suffix `Hostname` in rewritten collections with the same timestamp as the new `HostID` |

Only files whose name starts with `Collection` and ends with `.zip` are
processed. Files ending in `_altered.zip` are skipped so the script can be
re-run on a directory that already holds its own output. Everything else is
ignored.

The input and output directory may be the same. In that case altered ZIPs
are written beside the originals and unchanged ZIPs are left where they are.

Example:

```
python3 chk_hostid_raptor.py -i /cases/acme/collections -o /cases/acme/import-ready -r
```

### Why `-r` matters

Velociraptor's `Server.Utils.ImportCollection` artifact does not look at
`HostID` when ClientId is left at `auto`. It searches the client index for
the `Hostname` in `client_info.json` and, if a client with that name already
exists, imports into it. Clones of a template share a hostname, so a unique
`HostID` alone still lands every collection in the same client. With `-r`
the hostname becomes `<Hostname>-<timestamp>`, for example
`Win11-2026-090808553046`, so each import creates its own client. Only
`client_info.json` is changed; artifact results inside the collection still
show the real hostname.

## What it does

1. Reads `HostID` from `client_info.json` inside each ZIP. Nothing is
   extracted to disk.
2. Groups ZIPs by `HostID`. Any group with more than one member is a
   duplicate set.
3. Assigns a new `HostID` to **every** member of a duplicate set. None of
   them keeps the original value, which is the point: cloned VMs all carry
   the same ID and none of them is the "real" owner.
4. Writes each rewritten collection to the output directory as
   `<name>_altered.zip`. The archive is copied entry by entry, so entry
   timestamps, permissions, compression method, empty directories, and the
   archive comment are all preserved. Only `client_info.json` changes.
5. Copies every other ZIP to the output directory unchanged.
6. Prints one line per ZIP showing the old and new `HostID`.

Original ZIPs are never modified.

ZIPs the script cannot handle are reported with an `Error:` prefix, left
untouched, and copied to the output directory as-is. This covers a corrupt
ZIP, a missing or unparseable `client_info.json`, and a `HostID` that is
missing or not a string. Two ZIPs with the same error are not treated as
duplicates of each other.

## How the new HostID is built

The script keeps the first three dash-separated segments of the original ID
and appends a timestamp shaped as `YYYY-MMDDHHMMSSNN`, where `NN` is the
first two digits of the microseconds. For a UUID-style ID this preserves the
`8-4-4-4-12` shape:

```
before: 11111111-2222-3333-4444-555555555555
after:  11111111-2222-3333-2026-090712242332
```

An ID with fewer than three segments just gets `-<timestamp>` appended.
Uniqueness is guaranteed within a run. Across runs the 10 ms resolution
makes a collision practically impossible.

## Sample output

```
Collection_a.zip -> Old HostID: 1111...5555  =>  New HostID: 1111...-2026-090712242332 [UPDATED] -> /cases/acme/import-ready/Collection_a_altered.zip
Collection_b.zip -> Old HostID: 1111...5555  =>  New HostID: 1111...-2026-090712242333 [UPDATED] -> /cases/acme/import-ready/Collection_b_altered.zip
Collection_c.zip -> HostID: aaaa...eeee
Collection_d.zip -> HostID: Error: client_info.json not found
```

## Known limitations

- Encrypted collections are not supported. The script needs to read
  `client_info.json` in the clear.
- `client_info.json` is rewritten with four-space indentation, so its bytes
  differ from the original even where the content is the same.
- A ZIP that fails partway through writing leaves a partial `_altered.zip`
  in the output directory. Delete it and re-run.

## Changelog

- 2026-09-07: Rewritten to work on the ZIPs directly instead of extracting
  them. Altered archives now preserve entry timestamps, empty directories,
  compression, and the archive comment. Corrupt ZIPs and bad
  `client_info.json` files are reported instead of aborting the run. Missing
  or non-string `HostID` values are no longer treated as shared IDs. A
  relative `-o` resolves from the current directory, input and output may
  be the same directory, and `_altered.zip` files are skipped on re-runs.
- 2026-09-08: A relative `-o` now resolves beside the input directory, so
  `-i ./a -o ./b` creates `b` as a sibling of `a` from any working directory.
  Added `-r`/`--rename-hostname` to suffix `Hostname` with the timestamp,
  because the import artifact picks the client by hostname, not `HostID`.
