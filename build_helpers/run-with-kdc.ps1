#!/usr/bin/env pwsh
# Copyright: (c) 2026, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

<#
.SYNOPSIS
Runs a command with a Kerberos KDC for the pyspnego tests.

.DESCRIPTION
Starts an Obol KDC for the realm PYSPNEGO.TEST with a user and a service
principal, points the platform's Kerberos library at it and runs the command
given. The realm details are passed to the command as JSON in the
PYSPNEGO_TEST_KERBEROS environment variable, which the kerb_realm fixture in
tests/conftest.py reads. The Kerberos tests are skipped when it is not set.

On Linux and macOS the krb5 environment variables KRB5_CONFIG, KRB5CCNAME and
KRB5_KTNAME are set so MIT krb5 or Heimdal use the KDC. Set GSSAPI_PROVIDER to
mit or heimdal to write the krb5.conf for that library, the platform default is
used otherwise.

On Linux and macOS a TGT for the user is also stored in the credential cache
KRB5CCNAME points to, so default credentials authenticate as the test user.

On Windows the realm is registered with the Kerberos SSP machine wide, like
ksetup.exe /addkdc, which needs an elevated session. The user's credential is
stored in the Credential Manager for the service host for the same reason.

The Obol module is installed from the PowerShell Gallery if the version this
script uses is not already available.

.EXAMPLE
pwsh build_helpers/run-with-kdc.ps1 python -m pytest tests/test_auth.py -k kerberos
#>

$ErrorActionPreference = 'Stop'

if (-not $args) {
    throw 'A command to run with the KDC must be specified, for example: run-with-kdc.ps1 python -m pytest'
}
$command = $args[0]
$commandArgs = @($args | Select-Object -Skip 1)

$obolVersion = '0.1.0'
$baseVersion, $prerelease = $obolVersion -split '-', 2

function Get-ObolModule {
    Get-Module -Name Obol -ListAvailable | Where-Object {
        $_.Version -eq [Version]$baseVersion -and [string]$_.PrivateData.PSData.Prerelease -eq [string]$prerelease
    } | Select-Object -First 1
}

$obolModule = Get-ObolModule
if (-not $obolModule) {
    Write-Host "Installing Obol $obolVersion from the PowerShell Gallery"
    $installParams = @{
        Name = 'Obol'
        Version = $obolVersion
        Prerelease = [bool]$prerelease
        TrustRepository = $true
        Scope = 'CurrentUser'
        Quiet = $true
    }
    Install-PSResource @installParams

    $obolModule = Get-ObolModule
    if (-not $obolModule) {
        throw "Failed to find Obol $obolVersion after installing it"
    }
}
Import-Module -Name $obolModule.Path

function New-RandomPassword {
    [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(16))
}

$realm = 'PYSPNEGO.TEST'
$hostname = 'host.pyspnego.test'
$service = 'host'
$userPrincipal = 'user'
$userPassword = New-RandomPassword

# The tickets for the service are encrypted with the random keys of this
# account, which the acceptor reads from a keytab. Windows only delegates
# credentials to a service whose tickets have the OK-AS-DELEGATE flag, which
# TrustedForDelegation sets. The SSPI acceptor does not run as SYSTEM so it
# cannot verify a PAC, the tickets for the service are issued without one.
$acceptorPrincipal = 'service'

$kdcParams = @{
    Realm = $realm
    Principal = [ordered]@{
        $userPrincipal = New-ObolPrincipalSetting -Password (
            ConvertTo-SecureString -AsPlainText -Force $userPassword
        )
        $acceptorPrincipal = New-ObolPrincipalSetting -Alias "$service/$hostname" -Flag 'TrustedForDelegation, NoAuthDataRequired'
    }
}
if ($IsWindows) {
    # Windows Kerberos always contacts a KDC on port 88.
    $kdcParams.Port = 88
}

$tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "pyspnego-kdc-$([Guid]::NewGuid().ToString('N'))"
if ($IsWindows) {
    $null = New-Item -Path $tempPath -ItemType Directory
}
else {
    $null = [System.IO.Directory]::CreateDirectory($tempPath, [System.IO.UnixFileMode]'UserRead, UserWrite, UserExecute')
}

$exitCode = 1
$kdc = Start-ObolKdc @kdcParams
try {
    $clientKeytab = Join-Path $tempPath 'client.keytab'
    $acceptorKeytab = Join-Path $tempPath 'acceptor.keytab'
    Export-ObolKeytab -Path $clientKeytab -Kdc $kdc -Name $userPrincipal
    Export-ObolKeytab -Path $acceptorKeytab -Kdc $kdc -Name $acceptorPrincipal

    # SSPI has no credential cache, the Credential Manager is used instead.
    $ccache = if ($IsWindows) { $null } else { "FILE:$(Join-Path $tempPath 'ccache')" }

    $env:PYSPNEGO_TEST_KERBEROS = [ordered]@{
        realm = $realm
        kdc = $kdc.Endpoint.ToString()
        hostname = $hostname
        service = $service
        username = "$userPrincipal@$realm"
        password = $userPassword
        client_keytab = $clientKeytab
        acceptor_username = "$acceptorPrincipal@$realm"
        acceptor_keytab = $acceptorKeytab
        ccache = $ccache
    } | ConvertTo-Json -Compress

    Write-Host "Running '$command $commandArgs' with the KDC for $realm on $($kdc.Endpoint)"
    if ($IsWindows) {
        # The command runs in another process so the realm must be registered
        # for the whole machine, the per thread scope only applies to this one.
        Use-ObolSspiEnvironment -Kdc $kdc -Scope MitRealm {
            $cmdkey = Join-Path $env:SystemRoot 'System32\cmdkey.exe'
            $null = & $cmdkey /add:$hostname /user:"$userPrincipal@$realm" /pass:$userPassword
            if ($LASTEXITCODE) {
                throw "Failed to store the credential for $hostname with cmdkey.exe, exit code $LASTEXITCODE"
            }

            try {
                & $command @commandArgs
                $script:exitCode = $LASTEXITCODE
            }
            finally {
                $null = & $cmdkey /delete:$hostname
            }
        }
    }
    else {
        $krb5Params = @{
            Kdc = $kdc
            ServicePrincipal = $acceptorPrincipal
        }
        if ($env:GSSAPI_PROVIDER -eq 'heimdal') {
            $krb5Params.Provider = 'Heimdal'
        }
        elseif ($env:GSSAPI_PROVIDER -eq 'mit') {
            $krb5Params.Provider = 'Mit'
        }

        Use-ObolKrb5Environment @krb5Params {
            # Store a TGT for the user in a credential cache alongside the
            # keytabs, like cmdkey does for SSPI on Windows.
            $origKrb5Ccache = $env:KRB5CCNAME
            try {
                $env:KRB5CCNAME = $ccache
                kinit -k -t $clientKeytab "$userPrincipal@$realm"
                if ($LASTEXITCODE) {
                    throw "Failed to get a TGT for $userPrincipal with kinit, exit code $LASTEXITCODE"
                }

                & $command @commandArgs
                $script:exitCode = $LASTEXITCODE
            }
            finally {
                $env:KRB5CCNAME = $origKrb5Ccache
            }
        }
    }
}
finally {
    $kdc | Stop-ObolKdc
    Remove-Item -LiteralPath $tempPath -Recurse -Force -ErrorAction SilentlyContinue
}

exit $exitCode
