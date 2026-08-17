#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Config,

    [Parameter(Mandatory = $true)]
    [string]$Inventory,

    [Parameter(Mandatory = $true)]
    [string]$Spec,

    [Parameter(Mandatory = $true)]
    [string]$Output,

    [string]$Title = "Elastispec firewall audit"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-InputFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label file not found: $Path"
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

try {
    $configPath = Resolve-InputFile -Path $Config -Label "config"
    $inventoryPath = Resolve-InputFile -Path $Inventory -Label "inventory"
    $specPath = Resolve-InputFile -Path $Spec -Label "spec"

    $outputPath = [System.IO.Path]::GetFullPath($Output)
    if (-not $outputPath.EndsWith(".html", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "output must end in .html: $Output"
    }

    if (Test-Path -LiteralPath $outputPath -PathType Container) {
        throw "output path is a directory: $Output"
    }

    $outputDirectory = [System.IO.Path]::GetDirectoryName($outputPath)
    $outputName = [System.IO.Path]::GetFileName($outputPath)
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

    $auditorDirectory = Split-Path -Parent $PSScriptRoot
    $composeFile = Join-Path $auditorDirectory "compose.yaml"

    & docker compose version *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose is unavailable. Start Docker Desktop and enable Linux containers."
    }

    & docker compose -f $composeFile pull --policy missing
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to pull the Elastispec Docker images"
    }

    $env:ELASTISPEC_AUDITOR_CONFIG = $configPath
    $env:ELASTISPEC_AUDITOR_INVENTORY = $inventoryPath
    $env:ELASTISPEC_AUDITOR_SPEC = $specPath
    $env:ELASTISPEC_AUDITOR_OUTPUT_DIR = $outputDirectory
    $env:ELASTISPEC_AUDITOR_OUTPUT_NAME = $outputName
    $env:ELASTISPEC_AUDITOR_TITLE = $Title

    $status = 1
    try {
        & docker compose -f $composeFile up `
            --abort-on-container-exit `
            --exit-code-from auditor `
            --attach auditor
        $status = $LASTEXITCODE

        if ($status -ne 0) {
            [Console]::Error.WriteLine("Batfish logs (last 200 lines):")
            & docker compose -f $composeFile logs `
                --no-color --tail 200 batfish
        }
    }
    finally {
        & docker compose -f $composeFile down --volumes *> $null
    }

    if ($status -ne 0) {
        exit $status
    }

    Write-Host "Report: $outputPath"
}
catch {
    [Console]::Error.WriteLine("error: $($_.Exception.Message)")
    exit 2
}
