# askWAM BOF

This directory contains the x64 Beacon Object File adapter for the plain-C WAM
flow. It is silent-only, operates in the Beacon process and current user's context,
and does not inspect WAM cache files.

Build:

```powershell
.\build.ps1 -Configuration Release
```

The output is `bin\Release\askwam_bof.x64.o`. Load `askwam.cna` in the Cobalt
Strike Script Manager, then run `help askwam` in a Beacon console.

To run Fortra's BOFlint during the build, point `BOFLINT_PATH` at the standalone
`boflint.py` distributed in the official Cobalt Strike BOF-VS repository:

```powershell
$env:BOFLINT_PATH = 'C:\path\to\bof-vs\BOF-Template\utils\boflint.py'
.\build.ps1 -Configuration Release
```

The defaults are the Teams desktop/mobile client ID, Graph `.default`, the
`organizations` authority, WAM's default account, a 30-second timeout, and visible
token output. `--scope` uses the v2-compatible scope flow; `--resource` uses an
empty scope and WAM's v1-compatible `resource` request property. The two options
are mutually exclusive. Examples:

```text
askwam --enum
askwam --account-id <id-from-enum>
askwam --username user@example.com
askwam --resource https://graph.microsoft.com --hide
askwam --cae
askwam --cae --hide
askwam --claims-json {"access_token":{"xms_cc":{"values":["cp1"]}}}
```

`--account-id` is the canonical selector. `--username` requires exactly one
case-insensitive match. `--cae` and `--claims-json` are mutually exclusive; include
`cp1` in the raw object when a custom challenge also requires CAE.

The BOF uses direct function resolution for inbox `combase` and `kernel32` APIs.
It uses no MSAL, .NET, C++/WinRT, CRT, callbacks, worker threads, or cache access.

## Cobalt Strike
A `.cna` file is included in the repository to load the BOF.

## Sliver

`extension.json` is a ready-to-load Sliver extension manifest for the Release
object. Build the BOF first, install Sliver's COFF loader, and load this directory:

```text
armory install coff-loader
extensions load C:\absolute\path\to\wamask\src\bof
```

Sliver packs the manifest arguments in their declared order, matching the
`zzzzzzziiii` contract used by the CNA adapter. Sliver's integer switches take an
explicit `0` or `1` value:

```text
askwam --enum 1
askwam --resource https://graph.microsoft.com --hide 1
askwam --cae 1 --hide 1
```

All eleven arguments are optional in the manifest. Missing values are packed as
empty strings or zeroes, except `timeout-seconds`, which defaults to 30. The BOF
itself validates incompatible combinations.

## Mythic Apollo

Apollo does not consume Sliver's extension manifest and no Mythic sidecar JSON is
required. Upload or register `bin\Release\askwam_bof.x64.o`, then run Apollo's
`execute_coff` command with function `go`, timeout 30, and this exact typed-array
order:

| Position | Apollo type | Value |
| --- | --- | --- |
| 1 | `string` | client ID, or empty |
| 2 | `string` | scope, or empty |
| 3 | `string` | resource, or empty |
| 4 | `string` | authority, or empty |
| 5 | `string` | raw claims JSON, or empty |
| 6 | `string` | account ID, or empty |
| 7 | `string` | username, or empty |
| 8 | `int32` | timeout seconds |
| 9 | `int32` | hide token: 0 or 1 |
| 10 | `int32` | CAE: 0 or 1 |
| 11 | `int32` | enumerate: 0 or 1 |

Apollo's task JSON represents `coff_arguments` as pairs such as
`["string", ""]` and `["int32", 30]`. Keep all eleven entries, including empty
placeholders, because their position is the BOF ABI. Forge can optionally provide
a named Mythic command wrapper, but it is not required for `execute_coff`.
