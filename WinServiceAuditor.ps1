Add-Type @"
[System.FlagsAttribute]
public enum ServiceAccessFlags : uint
{
    QueryConfig = 1,
    ChangeConfig = 2,
    QueryStatus = 4,
    EnumerateDependents = 8,
    Start = 16,
    Stop = 32,
    PauseContinue = 64,
    Interrogate = 128,
    UserDefinedControl = 256,
    Delete = 65536,
    ReadControl = 131072,
    WriteDac = 262144,
    WriteOwner = 524288,
    Synchronize = 1048576,
    AccessSystemSecurity = 16777216,
    GenericAll = 268435456,
    GenericExecute = 536870912,
    GenericWrite = 1073741824,
    GenericRead = 2147483648
}
"@

function Get-ServiceAcl {
    param (
        [Parameter(Mandatory)]
        [string]$ServiceName
    )

    $sc = "$env:SystemRoot\System32\sc.exe"
    $sddl = & $sc sdshow $ServiceName 2>$null | Where-Object { $_ }

    if (-not $sddl) { return $null }

    try {
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)
    } catch {
        return $null
    }

    foreach ($ace in $sd.DiscretionaryAcl) {

        try {
            $identity = $ace.SecurityIdentifier.Translate(
                [System.Security.Principal.NTAccount]
            )
        } catch {
            $identity = $ace.SecurityIdentifier.Value
        }

        [PSCustomObject]@{
            Identity = $identity
            Rights   = [ServiceAccessFlags]$ace.AccessMask
            Type     = $ace.AceType
        }
    }
}

Write-Host "`n[+] Enumerating services..." -ForegroundColor Cyan

$Services = Get-CimInstance Win32_Service | Where-Object {
    $_.StartName -match "LocalSystem|NT AUTHORITY\\SYSTEM"
}

foreach ($Service in $Services) {

    $Acls = Get-ServiceAcl -ServiceName $Service.Name
    if (-not $Acls) { continue }

    foreach ($Ace in $Acls) {

        if ($Ace.Identity -match "SYSTEM|Administrators") {
            continue
        }

        if ($Ace.Rights.ToString() -match "ChangeConfig|WriteDac|WriteOwner|GenericAll") {

            Write-Host "`n[!] Potential Service Misconfiguration Found" -ForegroundColor Red
            Write-Host "    Service Name : $($Service.Name)"
            Write-Host "    Display Name: $($Service.DisplayName)"
            Write-Host "    Runs As     : $($Service.StartName)"
            Write-Host "    Identity    : $($Ace.Identity)"
            Write-Host "    Rights      : $($Ace.Rights)"
            Write-Host "    Start Mode  : $($Service.StartMode)"
            Write-Host "    Binary Path : $($Service.PathName)"
        }
    }
}

Write-Host "`n[+] Audit complete.`n" -ForegroundColor Green
