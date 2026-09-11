# askWAM

`askWAM` requests Microsoft Entra access tokens silently through Windows Web
Account Manager (WAM). It ships as a .NET Framework client, a standalone native
x64 client, and an x64 Beacon Object File with a CNA command adapter.

All frontends can enumerate accounts visible to the client and target an identity
by its opaque WAM account ID or exact username. They never fall back to interactive
authentication.

Tokens requested via this flow will inherit the following details:
- User auth methods
- Device state like compliant/hybrid joined or managed

This way of requesting tokens also works when Token Protection is enforced. 
CAE tokens can be requested with the `--cae` flag.

## Defaults

- Microsoft Teams desktop/mobile client ID:
  `1fec8e78-bce4-4aaf-ab1b-5451cc387264`
- Scope: `https://graph.microsoft.com/.default`
- Authority: `organizations`
- WAM's default account when no selector is supplied
- 30-second timeout
- Access-token output enabled; `--hide` suppresses it

The default Graph scope is selected only when neither `--scope` nor `--resource`
is supplied.

## Request modes

Scope mode accepts one or more v2 scopes. It appends
`openid offline_access profile` and sets WAM's `wam_compat=2.0` request property.

```text
askwam --scope https://graph.microsoft.com/.default
```

Resource mode implements WAM's v1-compatible flow. It sends an empty scope, sets
the WAM `resource` request property, and does not set `wam_compat`.

```text
askwam --resource https://graph.microsoft.com
```

`--scope` and `--resource` are mutually exclusive.

## Accounts and claims

```text
--enum                    Enumerate accounts without requesting a token
--account-id <id>         Select an exact opaque WAM account ID
--username <username>     Select one exact, unique username
--cae                     Send the predefined xms_cc/cp1 claims object
--claims-json <json>      Send a raw OAuth claims object or challenge
```

The .NET client additionally supports `--claims-file <path>` to read a raw OAuth
claims object from a UTF-8 file. `--cae` is mutually exclusive with custom claims
input. Include `cp1` in the raw object when a custom challenge also requires CAE.

## .NET Framework client

Deployment requires Windows with .NET Framework 4.8. The release directory
contains the application and its runtime configuration; it does not contain a
private .NET or WinRT runtime.

Building requires the .NET SDK and Windows SDK 10.0.26100.0 metadata by default.
Set the `WindowsMetadataPath` MSBuild property when using another installed
Windows 10 or Windows 11 SDK.

```powershell
dotnet build .\src\dotnet\AskWAM.csproj --configuration Release
.\src\dotnet\bin\Release\net48\askwam.exe --enum
.\src\dotnet\bin\Release\net48\askwam.exe --resource https://graph.microsoft.com --hide
```

The client writes plain `name=value` lines. It does not decode or print JWT claims.

## Standalone native client

Building requires Visual Studio 2022 C++ Build Tools and a Windows 10 or Windows
11 SDK. Account enumeration requires Windows 10 version 1803 or newer.

```powershell
.\src\native\build.ps1 -Configuration Release
.\src\native\bin\Release\askwam.exe --enum
.\src\native\bin\Release\askwam.exe --resource https://graph.microsoft.com --hide
```

The release executable is statically linked to the C runtime and uses the inbox
WinRT API surface. Its machine-readable result format is JSON.

## Beacon Object File

Build the x64 BOF and load `src\bof\askwam.cna` in Cobalt Strike:

```powershell
.\src\bof\build.ps1 -Configuration Release
```

```text
askwam --enum
askwam --account-id <id-from-enum>
askwam --resource https://graph.microsoft.com --hide
askwam --cae --hide
askwam --claims-json {"access_token":{"xms_cc":{"values":["cp1"]}}}
```

The build script checks the BOF entry point and undefined-symbol allowlist. When
`-BofLintPath` or `BOFLINT_PATH` names Outflank's `boflint.py`, it also validates
the release object for the Cobalt Strike, Outflank C2, and Core Impact loader
profiles.

The project also ships `src\bof\extension.json` for loading the Release BOF as a
Sliver extension. Mythic Apollo needs no equivalent sidecar file; its
`execute_coff` command accepts the object and the same typed argument sequence.
See `src\bof\README.md` for both integrations and the packed argument contract.

## References
Official documentation:
- [Web Account Manager desktop guide](https://learn.microsoft.com/en-us/windows/apps/develop/security/web-account-manager) — direct Windows WAM APIs and desktop integration.
- [Microsoft Entra WAM API reference](https://learn.microsoft.com/en-us/entra/identity-platform/reference-entra-id-wam-api) — provider-specific request parameters.
- [Using MSAL.NET with WAM](https://learn.microsoft.com/en-us/entra/msal/dotnet/acquiring-tokens/desktop-mobile/wam) — broker integration and the managed reference approach.
- [Claims challenges and client capabilities](https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge) — claims requests and CAE client capabilities.

Similar projects:
- [list-wam-accounts by Tw1sm](https://github.com/Tw1sm/list-wam-accounts)
- [go-wam by Allow-Solutions](https://github.com/allod-solutions/go-wam)

This project was created by Codex using GPT 5.6 Sol.