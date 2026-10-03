#Requires -Version 7.4
<#
.SYNOPSIS
    Opens a pull request for every new browser version that Capture.ps1 exported.

.DESCRIPTION
    For each <Profile>.json under -ArtifactsDirectory (written next to <Profile>.cs and Latest/<Alias>.cs by the inspector):
    - skips it when src/Chameleon.Net/Profiles/BuiltIn/<Profile>.cs already exists on the base branch, or when a pull request
      for it is already open;
    - otherwise, on branch profiles/<name>: adds the profile, points its "latest" alias at it, builds and runs the offline tests
      (which put every built-in profile through the inspector), commits, pushes and opens a pull request with the fingerprints,
      the inspector's findings, the capture notes and the changes from the previous version. A failing build or test run still
      opens the pull request, as a draft.

    Needs git, and gh authenticated through GH_TOKEN with contents and pull request write access.

.EXAMPLE
    ./eng/profile-capture/Propose.ps1 -ArtifactsDirectory artifacts/profiles -DryRun
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ArtifactsDirectory,

    [string] $BaseBranch = 'master',

    # Build, test and print the pull request bodies in the current working tree, then put back the files it replaced: no branch,
    # commit, push or pull request.
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repository = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$ArtifactsDirectory = (Resolve-Path $ArtifactsDirectory).Path
Set-Location $repository
$builtIn = 'src/Chameleon.Net/Profiles/BuiltIn'

function Invoke-Native {
    param([Parameter(Mandatory)] [string] $Command, [string[]] $Arguments = @())
    & $Command @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "$Command $($Arguments -join ' ') exited with $LASTEXITCODE."
    }
}

function Get-AliasTarget([string] $Path) {
    if (-not (Test-Path $Path)) {
        return $null
    }

    $match = [regex]::Match((Get-Content $Path -Raw), '=>\s*(\w+)\s*;')
    return $match.Success ? $match.Groups[1].Value : $null
}

# The previous version's file against the new one, with the property renamed so that only real changes show.
function Get-ProfileDiff([string] $Previous, [string] $Property, [string] $NewFile) {
    $previousFile = Join-Path $builtIn "$Previous.cs"
    if (-not $Previous -or -not (Test-Path $previousFile)) {
        return $null
    }

    $renamed = Join-Path ([IO.Path]::GetTempPath()) "$Previous.cs"
    (Get-Content $previousFile -Raw).Replace($Previous, $Property) | Set-Content $renamed -NoNewline
    $diff = (& git diff --no-index --no-color --unified=2 -- $renamed $NewFile) -join "`n"
    Remove-Item $renamed
    return $diff.Length -gt 50000 ? $diff.Substring(0, 50000) + "`n… (truncated)" : $diff
}

function New-PullRequestBody($Metadata, [string] $Previous, [string] $Diff, [bool] $Tested) {
    $run = $env:GITHUB_RUN_ID ? "[workflow run]($env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID)" : 'a local run'
    $ja3 = $Metadata.extensionShuffle ? 'changes per connection (extension shuffle)' : "``$($Metadata.ja3Hash)``"
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add("Automated capture of **$($Metadata.label)** with the Chameleon.Net Inspector ($run).")
    $lines.Add('')
    $lines.Add('| | |')
    $lines.Add('|---|---|')
    $lines.Add("| Profile | ``BuiltInProfiles.$($Metadata.property)`` (``$($Metadata.name)``) |")
    $lines.Add("| Alias | ``BuiltInProfiles.$($Metadata.alias)`` → ``$($Metadata.property)``$($Previous ? " (was ``$Previous``)" : ' (new)') |")
    $lines.Add("| User-Agent | ``$($Metadata.userAgent)`` |")
    $lines.Add("| JA4 | ``$($Metadata.ja4)`` |")
    $lines.Add("| JA3 | $ja3 |")
    $lines.Add("| Akamai | ``$($Metadata.akamai)`` |")
    $lines.Add("| Inspector verdict | $($Metadata.verdict) |")
    $lines.Add("| Build and offline tests | $($Tested ? 'passed' : '**failed**: see the workflow run; this pull request is a draft') |")

    if ($Metadata.findings.Count -gt 0) {
        $lines.Add('')
        $lines.Add('### Inspector findings')
        $Metadata.findings | ForEach-Object { $lines.Add("- **$($_.severity)** ``$($_.id)``: $($_.message)") }
    }

    $lines.Add('')
    $lines.Add('### Capture notes')
    $Metadata.notes | ForEach-Object { $lines.Add("- $_") }

    if ($Diff) {
        $lines.Add('')
        $lines.Add("<details><summary>Changes from <code>$Previous</code></summary>")
        $lines.Add('')
        $lines.Add('```diff')
        $lines.Add($Diff)
        $lines.Add('```')
        $lines.Add('</details>')
    }

    $lines.Add('')
    $lines.Add('### Review')
    $lines.Add('- [ ] The User-Agent and client hints are the real browser''s, with no automation or headless tells.')
    $lines.Add('- [ ] TLS and HTTP/2 changes from the previous version are expected (check against tls.peet.ws from a real install if in doubt).')
    $lines.Add('- [ ] Nothing important is missing from the capture notes.')
    $lines.Add('- [ ] Optional: a golden test with the expected JA4 and Akamai, and the README''s profile list.')
    return $lines -join "`n"
}

$exports = @(Get-ChildItem $ArtifactsDirectory -Recurse -File | Where-Object Extension -eq '.json')
if ($exports.Count -eq 0) {
    Write-Host 'Nothing was exported.'
    return
}

Invoke-Native git @('fetch', '-q', 'origin', $BaseBranch)
if (-not $DryRun) {
    Invoke-Native gh @('label', 'create', 'profile', '--description', 'Automated browser profile capture', '--color', '0E8A16', '--force')
}

$failures = 0
foreach ($file in $exports) {
    $metadata = Get-Content $file.FullName -Raw | ConvertFrom-Json
    $property = $metadata.property
    $target = "$builtIn/$property.cs"
    $aliasTarget = "$builtIn/Latest/$($metadata.alias).cs"
    $branch = "profiles/$($metadata.name -replace '_', '-')"

    & git cat-file -e "origin/${BaseBranch}:$target" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "$property is already built in."
        continue
    }

    if (-not $DryRun -and (& gh pr list --head $branch --state open --json number --jq 'length') -ne '0') {
        Write-Host "$property already has an open pull request ($branch)."
        continue
    }

    Write-Host "Proposing $property ($($metadata.label))"
    if ($DryRun) {
        $saved = @($target, $aliasTarget) | ForEach-Object { @{ Path = $_; Content = (Test-Path $_) ? (Get-Content $_ -Raw) : $null } }
    } else {
        Invoke-Native git @('checkout', '-q', '-B', $branch, "origin/$BaseBranch")
    }

    $previous = Get-AliasTarget $aliasTarget
    New-Item -ItemType Directory -Force (Split-Path $aliasTarget) | Out-Null
    Copy-Item (Join-Path $file.DirectoryName "$property.cs") $target
    Copy-Item (Join-Path $file.DirectoryName 'Latest' "$($metadata.alias).cs") $aliasTarget
    $diff = Get-ProfileDiff $previous $property $target

    $tested = $true
    try {
        Invoke-Native dotnet @('build', 'Chameleon.Net.slnx', '-c', 'Release', '-v', 'q', '-nologo')
        Invoke-Native dotnet @('test', '--solution', 'Chameleon.Net.slnx', '-c', 'Release', '--no-build')
    } catch {
        Write-Warning "$property doesn't pass the build and offline tests: $_"
        $tested = $false
        $failures++
    }

    $body = New-PullRequestBody $metadata $previous $diff $tested
    if ($DryRun) {
        Write-Host $body
        foreach ($entry in $saved) {
            if ($null -eq $entry.Content) { Remove-Item $entry.Path } else { Set-Content $entry.Path $entry.Content -NoNewline }
        }

        continue
    }

    Invoke-Native git @('add', '--', $target, $aliasTarget)
    Invoke-Native git @('-c', 'user.name=github-actions[bot]', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com',
        'commit', '-q', '-m', "Add the $property built-in profile", '-m', "Captured from $($metadata.label) by eng/profile-capture.")
    Invoke-Native git @('push', '-q', '--force', 'origin', $branch)

    $bodyFile = New-TemporaryFile
    Set-Content $bodyFile $body
    $arguments = @('pr', 'create', '--base', $BaseBranch, '--head', $branch, '--title', "Add the $property built-in profile", '--body-file', $bodyFile, '--label', 'profile')
    if (-not $tested) {
        $arguments += '--draft'
    }

    Invoke-Native gh $arguments
    Remove-Item $bodyFile
}

if (-not $DryRun) {
    Invoke-Native git @('checkout', '-q', '--detach', "origin/$BaseBranch")
}

if ($failures -gt 0) {
    throw "$failures proposed profile(s) failed the build or tests; their pull requests are drafts."
}
