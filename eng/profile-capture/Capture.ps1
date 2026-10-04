#Requires -Version 7.4
<#
.SYNOPSIS
    Captures the latest version of one browser with the Chameleon.Net Inspector and exports it as a built-in profile.

.DESCRIPTION
    Installs or updates the browser, trusts a throwaway certificate authority for the inspector, starts the inspector, and opens
    https://localhost:<port>/capture in a visible browser window (under xvfb on Linux) with a fresh profile. The capture page makes
    every kind of request an export needs, then asks the inspector for the profile, which it saves to -OutputDirectory:
    <Profile>.cs, Latest/<Alias>.cs and <Profile>.json (fingerprints, verdict, notes), plus the inspector's log and reports.

    Runs on GitHub-hosted Windows, macOS and Ubuntu runners (see .github/workflows/profiles.yml) and locally with -SkipInstall.
    Without -SkipInstall it installs or updates the browser. Everything else it changes on the machine (the trusted certificate
    authority, Firefox's policies.json, Edge's first-run policy) is undone when it finishes.

.EXAMPLE
    ./eng/profile-capture/Capture.ps1 -Browser edge -SkipInstall -NoTrust

    A local run that changes nothing on the machine: the installed Edge, told to ignore certificate errors instead of trusting
    the capture's certificate authority (Chromium-based browsers only).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('chrome', 'edge', 'firefox', 'brave', 'opera', 'safari')]
    [string] $Browser,

    [string] $OutputDirectory = (Join-Path $PSScriptRoot '..' '..' 'artifacts' 'profile-capture'),

    [int] $Port = 8443,

    [int] $TimeoutSeconds = 180,

    # Use the browser already installed.
    [switch] $SkipInstall,

    # Don't trust the capture's certificate authority (which needs administrator rights on Windows); start Chromium-based browsers
    # with --ignore-certificate-errors instead. That flag doesn't change what the browser sends. For local runs.
    [switch] $NoTrust
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repository = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$os = if ($IsWindows) { 'windows' } elseif ($IsMacOS) { 'macos' } else { 'linux' }
$work = Join-Path ([IO.Path]::GetTempPath()) "chameleon-capture-$Browser"
Remove-Item $work -Recurse -Force -ErrorAction Ignore
New-Item -ItemType Directory -Force $work, $OutputDirectory | Out-Null
$OutputDirectory = (Resolve-Path $OutputDirectory).Path

# Product: the profile's client family, passed to the inspector because Brave's User-Agent is Chrome's.
$browsers = @{
    chrome  = @{ Product = 'Chrome'; Name = 'Google Chrome'; Chromium = $true
                 windows = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe")
                 macos = '/Applications/Google Chrome.app'; linux = '/usr/bin/google-chrome-stable' }
    edge    = @{ Product = 'Edge'; Name = 'Microsoft Edge'; Chromium = $true
                 windows = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe")
                 macos = '/Applications/Microsoft Edge.app'; linux = '/usr/bin/microsoft-edge-stable' }
    firefox = @{ Product = 'Firefox'; Name = 'Mozilla Firefox'; Chromium = $false
                 windows = "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
                 macos = '/Applications/Firefox.app'; linux = '/usr/bin/firefox' }
    brave   = @{ Product = 'Brave'; Name = 'Brave'; Chromium = $true
                 windows = @("$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe", "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe")
                 macos = '/Applications/Brave Browser.app'; linux = '/usr/bin/brave-browser' }
    opera   = @{ Product = 'Opera'; Name = 'Opera'; Chromium = $true
                 windows = @("$env:LOCALAPPDATA\Programs\Opera\opera.exe", "$env:ProgramFiles\Opera\opera.exe")
                 macos = '/Applications/Opera.app'; linux = '/usr/bin/opera' }
    safari  = @{ Product = 'Safari'; Name = 'Safari'; Chromium = $false
                 macos = '/Applications/Safari.app' }
}
$spec = $browsers[$Browser]
if (-not $spec.ContainsKey($os)) {
    throw "$($spec.Name) doesn't run on $os."
}

if ($NoTrust -and -not $spec.Chromium) {
    throw "-NoTrust only works with Chromium-based browsers: $($spec.Name) needs the certificate authority trusted."
}

# Undo actions for every change made to the machine, run in reverse order at the end.
$restore = [Collections.Generic.List[scriptblock]]::new()

# Start-Process joins arguments with spaces without quoting them.
function Format-Arguments([object[]] $Arguments) {
    return $Arguments | ForEach-Object { if ("$_" -match '\s') { "`"$_`"" } else { "$_" } }
}

# Output goes to the console, not to the caller: inside a function it would otherwise become part of the return value.
function Invoke-Native {
    param([Parameter(Mandatory)] [string] $Command, [string[]] $Arguments = @())
    & $Command @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "$Command $($Arguments -join ' ') exited with $LASTEXITCODE."
    }
}

function Invoke-Download([string] $Uri, [string] $Name) {
    $path = Join-Path $work $Name
    Invoke-WebRequest -Uri $Uri -OutFile $path
    return $path
}

function Add-AptRepository([string] $Name, [string] $KeyUri, [string] $Source, [switch] $Dearmor) {
    $keyring = "/usr/share/keyrings/$Name.gpg"
    $key = Invoke-Download $KeyUri "$Name.key"
    if ($Dearmor) {
        Invoke-Native sudo @('gpg', '--batch', '--yes', '--dearmor', '-o', $keyring, $key)
    } else {
        Invoke-Native sudo @('cp', $key, $keyring)
    }

    $Source.Replace('{keyring}', $keyring) | sudo tee "/etc/apt/sources.list.d/$Name.list" | Out-Null
}

function Install-Browser {
    switch ($os) {
        'windows' {
            switch ($Browser) {
                'chrome' {
                    $msi = Invoke-Download 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi' 'chrome.msi'
                    Start-Process msiexec.exe -ArgumentList '/i', $msi, '/qn', '/norestart' -Wait
                }
                'firefox' {
                    $installer = Invoke-Download 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US' 'firefox.exe'
                    Start-Process $installer -ArgumentList '/S' -Wait
                }
                default {
                    $package = @{ edge = 'microsoft-edge'; brave = 'brave'; opera = 'opera' }[$Browser]
                    Invoke-Native choco @('upgrade', $package, '-y', '--no-progress')
                }
            }
        }
        'macos' {
            if ($Browser -ne 'safari') {
                $cask = @{ chrome = 'google-chrome'; edge = 'microsoft-edge'; firefox = 'firefox'; brave = 'brave-browser'; opera = 'opera' }[$Browser]
                # GitHub's runners turn Homebrew's automatic update off: without this, the latest versions it knows are the image's.
                Invoke-Native brew @('update', '--quiet')
                # Chrome and Edge update themselves, and Homebrew leaves such casks alone unless told to be greedy.
                & brew list --cask $cask *> $null
                if ($LASTEXITCODE -eq 0) {
                    Invoke-Native brew @('upgrade', '--cask', '--greedy', $cask)
                } else {
                    Invoke-Native brew @('install', '--cask', '--force', $cask)
                }
            }
        }
        'linux' {
            $env:DEBIAN_FRONTEND = 'noninteractive'
            switch ($Browser) {
                'chrome' {
                    $deb = Invoke-Download 'https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb' 'chrome.deb'
                    Invoke-Native sudo @('apt-get', 'install', '-y', $deb)
                    return
                }
                'edge' {
                    Add-AptRepository microsoft-edge 'https://packages.microsoft.com/keys/microsoft.asc' `
                        'deb [arch=amd64 signed-by={keyring}] https://packages.microsoft.com/repos/edge stable main' -Dearmor
                }
                'firefox' {
                    # Mozilla's own packages rather than Ubuntu's snap, which ignores system policies.
                    Add-AptRepository mozilla 'https://packages.mozilla.org/apt/repo-signing-key.gpg' `
                        'deb [signed-by={keyring}] https://packages.mozilla.org/apt mozilla main' -Dearmor
                    "Package: *`nPin: origin packages.mozilla.org`nPin-Priority: 1000`n" | sudo tee /etc/apt/preferences.d/mozilla | Out-Null
                }
                'brave' {
                    Add-AptRepository brave-browser 'https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg' `
                        'deb [signed-by={keyring}] https://brave-browser-apt-release.s3.brave.com/ stable main'
                }
                'opera' {
                    Add-AptRepository opera 'https://deb.opera.com/archive.key' 'deb [signed-by={keyring}] https://deb.opera.com/opera-stable/ stable non-free' -Dearmor
                }
            }

            $package = @{ edge = 'microsoft-edge-stable'; firefox = 'firefox'; brave = 'brave-browser'; opera = 'opera-stable' }[$Browser]
            Invoke-Native sudo @('apt-get', 'update', '-q')
            Invoke-Native sudo @('-E', 'apt-get', 'install', '-y', '-q', '--allow-downgrades', $package)
        }
    }
}

function Get-BrowserPath {
    $candidates = @($spec[$os])
    $path = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $path -and $os -eq 'windows') {
        # Installers move between per-user and machine-wide locations from one version to the next.
        $name = Split-Path $candidates[0] -Leaf
        $path = Get-ChildItem $env:LOCALAPPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)} -Filter $name -Recurse -Depth 4 -ErrorAction Ignore |
            Select-Object -First 1 -ExpandProperty FullName
    }

    if (-not $path) {
        throw "$($spec.Name) isn't installed (looked for $($candidates -join ', '))."
    }

    return $path
}

function Get-BrowserVersion([string] $Path) {
    switch ($os) {
        'windows' { return (Get-Item $Path).VersionInfo.ProductVersion }
        'macos' { return (& defaults read (Join-Path $Path 'Contents' 'Info.plist') CFBundleShortVersionString) }
        'linux' { return ((& $Path --version) -replace '[^\d.]', ' ').Trim().Split(' ')[0] }
    }
}

# A throwaway certificate authority, trusted for this run, and a localhost certificate it signs for the inspector. An authority
# rather than a trusted self-signed leaf: every certificate store (Windows, macOS keychain, NSS) accepts it the same way.
function New-CaptureCertificates {
    $ecdsa = [Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $sha256 = [Security.Cryptography.HashAlgorithmName]::SHA256
    $notBefore = [DateTimeOffset]::UtcNow.AddDays(-1)
    $notAfter = [DateTimeOffset]::UtcNow.AddDays(7)

    $authorityKey = [Security.Cryptography.ECDsa]::Create($ecdsa)
    $authorityRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Chameleon.Net profile capture (temporary)', $authorityKey, $sha256)
    $authorityRequest.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
    $authorityRequest.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new('KeyCertSign, CrlSign', $true))
    $authorityRequest.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($authorityRequest.PublicKey, $false))
    $authority = $authorityRequest.CreateSelfSigned($notBefore, $notAfter)

    $key = [Security.Cryptography.ECDsa]::Create($ecdsa)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=localhost', $key, $sha256)
    $names = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $names.AddDnsName('localhost')
    $names.AddIpAddress([Net.IPAddress]::Loopback)
    $names.AddIpAddress([Net.IPAddress]::IPv6Loopback)
    $request.CertificateExtensions.Add($names.Build())
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new('DigitalSignature', $true))
    $serverAuth = [Security.Cryptography.OidCollection]::new()
    $serverAuth.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1')) | Out-Null
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($serverAuth, $false))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509AuthorityKeyIdentifierExtension]::CreateFromCertificate($authority, $true, $false))
    $serial = [byte[]]::new(16)
    [Security.Cryptography.RandomNumberGenerator]::Fill($serial)
    $serial[0] = $serial[0] -band 0x7F
    $leaf = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($request.Create($authority, $notBefore, $notAfter, $serial), $key)

    $password = [Guid]::NewGuid().ToString('N')
    $files = @{
        Pfx = Join-Path $work 'localhost.pfx'
        Password = $password
        AuthorityCer = Join-Path $work 'authority.cer'
        AuthorityPem = Join-Path $work 'authority.pem'
        Thumbprint = $authority.Thumbprint
    }
    [IO.File]::WriteAllBytes($files.Pfx, $leaf.Export('Pfx', $password))
    [IO.File]::WriteAllBytes($files.AuthorityCer, $authority.Export('Cert'))
    [IO.File]::WriteAllText($files.AuthorityPem, $authority.ExportCertificatePem())
    return $files
}

# Returns whether the system trusts the authority now: macOS 26 runners refuse to change trust settings without a user.
function Add-TrustedAuthority($Certificates) {
    $thumbprint = $Certificates.Thumbprint
    switch ($os) {
        'windows' {
            Import-Certificate -FilePath $Certificates.AuthorityCer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
            $restore.Add({ Remove-Item "Cert:\LocalMachine\Root\$thumbprint" -ErrorAction Ignore }.GetNewClosure())
        }
        'macos' {
            # Changing trust settings needs an interactive authorization; older runners let this rule be relaxed, macOS 26 doesn't.
            & sudo security authorizationdb write com.apple.trust-settings.admin allow 2>&1 | Out-Host
            & sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $Certificates.AuthorityCer 2>&1 | Out-Host
            if ($LASTEXITCODE -ne 0) {
                return $false
            }

            $restore.Add({ & sudo security delete-certificate -Z $thumbprint /Library/Keychains/System.keychain | Out-Null }.GetNewClosure())
        }
        'linux' {
            # Chromium-based browsers on Linux read the user's NSS database.
            $database = "sql:$HOME/.pki/nssdb"
            New-Item -ItemType Directory -Force "$HOME/.pki/nssdb" | Out-Null
            if (-not (Test-Path "$HOME/.pki/nssdb/cert9.db")) {
                Invoke-Native certutil @('-d', $database, '-N', '--empty-password')
            }

            Invoke-Native certutil @('-d', $database, '-A', '-t', 'C,,', '-n', 'chameleon-capture', '-i', $Certificates.AuthorityPem)
            $restore.Add({ & certutil -d $database -D -n chameleon-capture | Out-Null }.GetNewClosure())
        }
    }

    return $true
}

# Writes a file (with sudo on Linux) and registers putting back what was there before.
function Set-RestorableFile([string] $Path, [string] $Content) {
    $previous = if (Test-Path $Path) { Get-Content $Path -Raw } else { $null }
    if ($os -eq 'linux') {
        Invoke-Native sudo @('mkdir', '-p', (Split-Path $Path))
        $Content | sudo tee $Path | Out-Null
        $restore.Add({ if ($null -eq $previous) { & sudo rm -f $Path } else { $previous | sudo tee $Path | Out-Null } }.GetNewClosure())
    } else {
        New-Item -ItemType Directory -Force (Split-Path $Path) | Out-Null
        Set-Content $Path $Content
        $restore.Add({ if ($null -eq $previous) { Remove-Item $Path -Force } else { Set-Content $Path $previous -NoNewline } }.GetNewClosure())
    }
}

# Firefox keeps its own certificate store: an enterprise policy installs the authority, and skips first-run pages and telemetry.
# None of it changes what Firefox sends to the inspector.
function Set-FirefoxPolicies([string] $BrowserPath, $Certificates) {
    $policies = @{
        policies = @{
            Certificates = @{ Install = @($Certificates.AuthorityPem); ImportEnterpriseRoots = $true }
            OverrideFirstRunPage = ''
            OverridePostUpdatePage = ''
            DisableTelemetry = $true
            DontCheckDefaultBrowser = $true
            DisableAppUpdate = $true
        }
    } | ConvertTo-Json -Depth 5
    $directory = switch ($os) {
        'windows' { Join-Path (Split-Path $BrowserPath) 'distribution' }
        'macos' { Join-Path $BrowserPath 'Contents' 'Resources' 'distribution' }
        'linux' { '/etc/firefox/policies' }
    }

    Set-RestorableFile (Join-Path $directory 'policies.json') $policies
}

# Edge's first-run experience otherwise opens over the capture tab.
function Set-EdgePolicies {
    switch ($os) {
        'windows' {
            $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            $previous = (Get-ItemProperty $key -Name HideFirstRunExperience -ErrorAction Ignore)?.HideFirstRunExperience
            if (-not (Test-Path $key)) {
                New-Item -Force $key | Out-Null
            }

            Set-ItemProperty $key HideFirstRunExperience 1 -Type DWord
            $restore.Add({
                if ($null -eq $previous) { Remove-ItemProperty $key HideFirstRunExperience } else { Set-ItemProperty $key HideFirstRunExperience $previous -Type DWord }
            }.GetNewClosure())
        }
        'macos' {
            $previous = & defaults read com.microsoft.Edge HideFirstRunExperience 2>$null
            Invoke-Native defaults @('write', 'com.microsoft.Edge', 'HideFirstRunExperience', '-bool', 'true')
            $restore.Add({
                if ($null -eq $previous) { & defaults delete com.microsoft.Edge HideFirstRunExperience } else { & defaults write com.microsoft.Edge HideFirstRunExperience -bool ($previous -eq '1') }
            }.GetNewClosure())
        }
        'linux' { Set-RestorableFile '/etc/opt/edge/policies/managed/chameleon-capture.json' '{ "HideFirstRunExperience": true }' }
    }
}

function Start-Inspector($Certificates, [string] $Label) {
    Invoke-Native dotnet @('build', (Join-Path $repository 'tools' 'Chameleon.Net.Inspector'), '-c', 'Release', '-v', 'q', '-nologo')
    $inspector = Join-Path $repository 'tools' 'Chameleon.Net.Inspector' 'bin' 'Release' 'net10.0' 'Chameleon.Net.Inspector.dll'
    $arguments = @(
        $inspector, '--port', $Port, '--cert', $Certificates.Pfx, '--cert-password', $Certificates.Password,
        '--export-dir', $OutputDirectory, '--export-format', 'builtin', '--export-client', $spec.Product,
        '--export-label', $Label, '--log', (Join-Path $OutputDirectory 'reports.jsonl'),
        '--connection-log', (Join-Path $OutputDirectory 'connections.jsonl'))
    $process = Start-Process dotnet -ArgumentList (Format-Arguments $arguments) -PassThru `
        -RedirectStandardOutput (Join-Path $OutputDirectory 'inspector.log') -RedirectStandardError (Join-Path $OutputDirectory 'inspector.err.log')

    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($process.HasExited) {
            throw "The inspector exited with $($process.ExitCode); see inspector.err.log."
        }

        $client = [Net.Sockets.TcpClient]::new()
        try {
            $client.Connect('127.0.0.1', $Port)
            return $process
        } catch {
            Start-Sleep -Milliseconds 500
        } finally {
            $client.Dispose()
        }
    }

    throw "The inspector didn't start listening on port $Port."
}

function Start-Browser([string] $BrowserPath, [string] $Url) {
    $profileDirectory = Join-Path $work 'profile'
    New-Item -ItemType Directory -Force $profileDirectory | Out-Null
    if ($Browser -eq 'safari') {
        Invoke-Native open @('-a', $BrowserPath, $Url)
        return $null
    }

    $executable = if ($os -eq 'macos') {
        Get-ChildItem (Join-Path $BrowserPath 'Contents' 'MacOS') -File | Where-Object Name -NotMatch 'helper|crashpad' | Select-Object -First 1 -ExpandProperty FullName
    } else {
        $BrowserPath
    }

    # Only flags that skip first-run screens: nothing that changes what the browser sends.
    $arguments = if ($spec.Chromium) {
        @("--user-data-dir=$profileDirectory", '--no-first-run', '--no-default-browser-check') + ($ignoreCertificateErrors ? @('--ignore-certificate-errors') : @()) + @($Url)
    } else {
        @('-profile', $profileDirectory, '-no-remote', '-new-instance', $Url)
    }

    # The browser's output goes to files: its helper processes would otherwise inherit this script's output, and a CI step
    # doesn't end while anything still holds that open.
    $logs = @{
        RedirectStandardOutput = Join-Path $OutputDirectory 'browser.log'
        RedirectStandardError = Join-Path $OutputDirectory 'browser.err.log'
    }
    if ($os -eq 'linux') {
        # A visible window on a virtual display: headless browsers announce themselves (HeadlessChrome) and differ in places.
        return Start-Process xvfb-run -ArgumentList (Format-Arguments (@('-a', '--server-args=-screen 0 1280x1024x24', $executable) + $arguments)) -PassThru @logs
    }

    return Start-Process $executable -ArgumentList (Format-Arguments $arguments) -PassThru @logs
}

# By the profile directory on the command line rather than the started process: browsers relaunch themselves (Edge does on a
# fresh profile), leaving the first process gone and the real one running.
function Stop-Browser($Process) {
    if ($Browser -eq 'safari') {
        & osascript -e 'quit app "Safari"' 2>$null | Out-Null
        return
    }

    if ($Process -and -not $Process.HasExited) {
        $Process.Kill($true)
    }

    $profileDirectory = Join-Path $work 'profile'
    if ($os -eq 'windows') {
        Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($profileDirectory) } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Ignore }
    } else {
        & pkill -f $profileDirectory 2>$null | Out-Null
    }

    if ($os -eq 'macos' -and $env:GITHUB_ACTIONS -eq 'true') {
        # Some macOS helpers (GPU, network, crashpad) don't carry the profile directory: on a runner, everything from the app goes.
        & pkill -f (Join-Path $browserPath 'Contents') 2>$null | Out-Null
    }
}

# A virtual display, NSS's certutil, and the GNOME settings schemas without which Opera aborts at startup.
if ($os -eq 'linux') {
    $missing = @('xvfb', 'libnss3-tools', 'gsettings-desktop-schemas') | Where-Object { & dpkg -s $_ *> $null; $LASTEXITCODE -ne 0 }
    if ($missing) {
        Invoke-Native sudo @('apt-get', 'update', '-q')
        Invoke-Native sudo (@('apt-get', 'install', '-y', '-q') + $missing)
    }
}

if (-not $SkipInstall) {
    Write-Host "Installing the latest $($spec.Name)…"
    try {
        Install-Browser
    } catch {
        Write-Warning "Installing $($spec.Name) failed ($_); using the installed version if there is one."
    }
}

$browserPath = Get-BrowserPath
$version = Get-BrowserVersion $browserPath
$runner = if ($env:GITHUB_ACTIONS -eq 'true') { "GitHub Actions $env:ImageOS (image $env:ImageVersion)" } else { [Runtime.InteropServices.RuntimeInformation]::OSDescription.Trim() }
$label = "$($spec.Name) $version on $runner"
Write-Host "Capturing $label"

$inspector = $null
$browserProcess = $null
try {
    $certificates = New-CaptureCertificates
    $ignoreCertificateErrors = $NoTrust.IsPresent
    if (-not $NoTrust -and -not (Add-TrustedAuthority $certificates)) {
        # Firefox installs the authority from its own policy; Chromium-based browsers can ignore the error, which changes nothing
        # in what they send. Safari has no such option.
        if ($Browser -eq 'safari') {
            throw "This runner refused to trust the capture's certificate authority, and Safari can't be told to ignore it."
        }

        Write-Warning 'This runner refused to trust the capture''s certificate authority; ignoring certificate errors instead.'
        $ignoreCertificateErrors = $spec.Chromium
    }

    if ($Browser -eq 'firefox') {
        Set-FirefoxPolicies $browserPath $certificates
    }

    if ($Browser -eq 'edge' -and -not $NoTrust) {
        Set-EdgePolicies
    }

    $inspector = Start-Inspector $certificates $label
    $browserProcess = Start-Browser $browserPath "https://localhost:$Port/capture"

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $metadata = $null
    while (-not $metadata -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds 2
        $metadata = Get-ChildItem $OutputDirectory -File | Where-Object Extension -eq '.json' | Select-Object -First 1
    }

    if (-not $metadata) {
        Get-Content (Join-Path $OutputDirectory 'inspector.log') -Tail 60 -ErrorAction Ignore | Write-Host
        throw "No export from $($spec.Name) within $TimeoutSeconds seconds; the inspector's log is above and in the artifacts."
    }

    $export = Get-Content $metadata.FullName -Raw | ConvertFrom-Json
    Write-Host "Exported $($export.property): JA4 $($export.ja4), Akamai $($export.akamai), verdict $($export.verdict)."
    $export.notes | ForEach-Object { Write-Host "  - $_" }
} finally {
    # Each step on its own: a browser or inspector left running would also keep the job's output open.
    try {
        Stop-Browser $browserProcess
    } catch {
        Write-Warning "Couldn't stop $($spec.Name): $_"
    }

    try {
        if ($inspector -and -not $inspector.HasExited) {
            $inspector.Kill($true)
        }
    } catch {
        Write-Warning "Couldn't stop the inspector: $_"
    }

    for ($i = $restore.Count - 1; $i -ge 0; $i--) {
        try {
            & $restore[$i]
        } catch {
            Write-Warning "Couldn't undo a change to this machine: $_"
        }
    }
}
