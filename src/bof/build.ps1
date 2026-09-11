[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$BofLintPath = $env:BOFLINT_PATH
)

$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) {
    throw 'Visual Studio C++ Build Tools were not found.'
}

$vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat'
$source = Join-Path $PSScriptRoot 'askwam_bof.c'
$output = Join-Path $PSScriptRoot "bin\$Configuration"
New-Item -ItemType Directory -Force -Path $output | Out-Null

$flags = if ($Configuration -eq 'Release') { '/O2 /DNDEBUG' } else { '/Od /Zi' }
$command = '"{0}" >nul && cl.exe /nologo /W4 /c /GS- /Zl /Oi {1} /DUNICODE /D_UNICODE /Fo:"{2}\askwam_bof.x64.o" /Tc"{3}"' -f $vcvars, $flags, $output, $source
& $env:ComSpec /d /s /c $command
if ($LASTEXITCODE -ne 0) {
    throw "BOF build failed with exit code $LASTEXITCODE."
}

$object = Join-Path $output 'askwam_bof.x64.o'
$symbolCommand = '"{0}" >nul && dumpbin.exe /nologo /symbols "{1}"' -f $vcvars, $object
$symbols = & $env:ComSpec /d /s /c $symbolCommand
if ($LASTEXITCODE -ne 0) {
    throw "Could not inspect BOF symbols (exit code $LASTEXITCODE)."
}

$allowed = @(
    '__imp_BeaconDataParse', '__imp_BeaconDataInt', '__imp_BeaconDataExtract',
    '__imp_BeaconPrintf',
    '__imp_COMBASE$RoInitialize', '__imp_COMBASE$RoUninitialize',
    '__imp_COMBASE$RoGetActivationFactory', '__imp_COMBASE$WindowsCreateString',
    '__imp_COMBASE$WindowsDeleteString', '__imp_COMBASE$WindowsGetStringRawBuffer',
    '__imp_KERNEL32$GetTickCount64', '__imp_KERNEL32$Sleep',
    '__imp_KERNEL32$GetProcessHeap', '__imp_KERNEL32$HeapAlloc',
    '__imp_KERNEL32$HeapFree', '__imp_KERNEL32$MultiByteToWideChar',
    '__imp_KERNEL32$WideCharToMultiByte', '__imp_KERNEL32$CompareStringOrdinal'
)
$unexpected = foreach ($line in $symbols) {
    if ($line -match 'UNDEF\s+notype\s+External\s+\|\s+(\S+)') {
        $name = $Matches[1]
        if ($name -notin $allowed) { $name }
    }
}
if ($unexpected) {
    throw "Unexpected undefined BOF symbols: $($unexpected -join ', ')"
}
if (-not ($symbols | Select-String -Pattern '\| go$' -Quiet)) {
    throw 'The BOF object does not export the go entry point.'
}

if ($BofLintPath) {
    $resolvedBofLint = (Resolve-Path -LiteralPath $BofLintPath -ErrorAction Stop).Path
    foreach ($loader in @('cs', 'oc2', 'ci')) {
        & py -3 $resolvedBofLint --nocolor --loader $loader $object
        if ($LASTEXITCODE -ne 0) {
            throw "BOFlint rejected the object for loader '$loader' with exit code $LASTEXITCODE."
        }
    }
}
