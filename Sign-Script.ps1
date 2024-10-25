[CmdletBinding(DefaultParameterSetName = 'Thumbprint')]

param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
    [string]
    $Thumbprint,

    [Parameter(Mandatory = $true, ParameterSetName = 'SerialNumber')]
    [string]
    $SerialNumber,

    [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
    [Parameter(Mandatory = $true, ParameterSetName = 'SerialNumber')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Select')]
    [string]
    $Path,

    [Parameter(Mandatory = $true, ParameterSetName = 'Select')]
    [switch]
    $Select = $false,

    [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
    [Parameter(Mandatory = $true, ParameterSetName = 'SerialNumber')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Select')]
    [ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')]
    [string]
    $HasAlgorithm = 'SHA256',
    

    [Parameter(Mandatory = $false, ParameterSetName = 'Help')]
    [switch] $Help = $false
)

if ($PSCmdlet.ParameterSetName -eq 'Help') {
    Write-Host ''
    Write-Host '############################################' -ForegroundColor Cyan
    Write-Host '#####                                  #####' -ForegroundColor Cyan
    Write-Host '#####    Help for "Sign-Script.ps1"    #####' -ForegroundColor Cyan
    Write-Host '#####                                  #####' -ForegroundColor Cyan
    Write-Host '############################################' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '# Syntax' -ForegroundColor Cyan
    Write-Host '    .\Sign-Script.ps1 ' -ForegroundColor Yellow
    Write-Host '        -Thumbprint <string>' -ForegroundColor Blue
    Write-Host '        -Path <string>' -ForegroundColor Blue
    Write-Host '        [-HashAlgoritm <string>]' -ForegroundColor White
    Write-Host ''
    Write-Host '    .\Sign-Script.ps1 ' -ForegroundColor Yellow
    Write-Host '        -SerialNumber <string>' -ForegroundColor Blue
    Write-Host '        -Path <string>' -ForegroundColor Blue
    Write-Host '        [-HashAlgoritm <string>]' -ForegroundColor White
    Write-Host ''
    Write-Host '    .\Sign-Script.ps1 ' -ForegroundColor Yellow
    Write-Host '        -Path <string>' -ForegroundColor Blue
    Write-Host '        -Select' -ForegroundColor Blue
    Write-Host '        [-HashAlgoritm <string>]' -ForegroundColor White
    Write-Host ''
    Write-Host '    .\Sign-Script.ps1 ' -ForegroundColor Yellow
    Write-Host '        -Help' -ForegroundColor Blue
    Write-Host ''
    Write-Host '# Examples' -ForegroundColor Cyan
    Write-Host '    .\Sign-Script.ps1 ' -ForegroundColor Yellow -NoNewline
    Write-Host '-Thumbprint ' -ForegroundColor DarkGray  -NoNewline
    Write-Host '"5D4D95B7C367C1273CDB1726ED4C5307CF1D0C2B" ' -ForegroundColor Blue -NoNewline
    Write-Host '-Path ' -ForegroundColor DarkGray -NoNewline
    Write-Host '"C:\script.ps1" '-ForegroundColor Blue
    Write-Host '    Signs the script at "C:\script.ps1" with the certificate with the thumbprint "5D4D95B7C367C1273CDB1726ED4C5307CF1D0C2B"'
    Write-Host ''
    Write-Host '    .\Sign-Script.ps1 ' -ForegroundColor Yellow -NoNewline
    Write-Host '-SerialNumber ' -ForegroundColor DarkGray  -NoNewline
    Write-Host '"36af5e9b8a1cfa84484f8d2b37c4e96e" ' -ForegroundColor Blue -NoNewline
    Write-Host '-Path ' -ForegroundColor DarkGray -NoNewline
    Write-Host '"C:\script.ps1" '-ForegroundColor Blue
    Write-Host '    Signs the script at "C:\script.ps1" with the certificate with the serial number "36af5e9b8a1cfa84484f8d2b37c4e96e"'
    Write-Host ''
    Write-Host '    .\Sign-Script.ps1 ' -ForegroundColor Yellow -NoNewline
    Write-Host '-Path ' -ForegroundColor DarkGray -NoNewline
    Write-Host '"C:\script.ps1" '-ForegroundColor Blue -NoNewline
    Write-Host '-Select ' -ForegroundColor DarkGray 
    Write-Host '    Shows a list of all code signing certificates at "Cert:\CurrentUser\My", allows for selection and then signs the script at "C:\script.ps1" with the certificate selected'
    Write-Host ''
    Write-Host '# Parameters' -ForegroundColor Cyan
    Write-Host '    -HashAlgorithm' -ForegroundColor Green
    Write-Host '        Select the hash algorithm.'
    Write-Host '        Possible values:'
    Write-Host '            MD5'
    Write-Host '            SHA1'
    Write-Host '            SHA256'
    Write-Host '            SHA384'
    Write-Host '            SHA512'
    Write-Host ''
    Write-Host '    -Help' -ForegroundColor Green
    Write-Host '        Displays this help page'
    Write-Host ''
    Write-Host '    -Path [Path to the script to sign]' -ForegroundColor Green
    Write-Host '        The path to the script to sign.'
    Write-Host ''
    Write-Host '    -Select' -ForegroundColor Green
    Write-Host '        Flag for showing the certificate selection dialog. Only code signing certificates in "Cert:\CurrentUser\My" are shown.'
    Write-Host ''
    Write-Host '    -SerialNumber [Serial number of the certificate to use]' -ForegroundColor Green
    Write-Host '        The serial number of the code signing certificate to use for signing.'
    Write-Host ''
    Write-Host '    -Thumbprint [Thumprint of the certificate to use]' -ForegroundColor Green
    Write-Host '        The thumbprint of the code signing certificate to use for signing.'
    Write-Host ''
    Write-Host ''


    exit
}

$certStorePath = 'Cert:\CurrentUser\My'

if ($true -eq $Select) {
    $certs = Get-ChildItem $certStorePath -CodeSigningCert 
    Do {
        $counter = 0
        $certs | ForEach-Object {        
            Write-Host "$(' ' * (3 - ([string]$counter).Length))$($counter): " -NoNewline
            Write-Host "$(' ' * (42 - ($_.Thumbprint.Length)))$($_.Thumbprint), " -NoNewline
            Write-Host "$(' ' * (40 - ($_.SerialNumber.Length)))$($_.SerialNumber), " -NoNewline
            Write-Host "$($_.Subject), " 

            [int]$counter += 1
        }
        Write-Host ''
        Write-Host '  Q:   Quit'
        Write-Host ''
        $result = Read-Host -Prompt "Select a certificate"

        if ('Q' -eq $result) {
            Clear-Host
            return
        }
        
        if ((-not ($result -match "^(\d+|\.\d+|\d+\.\d+)$")) -or (([int]$result + 1) -gt $certs.Length) -or ([int]$result -lt 0)) {
            Write-Warning "Invalid Choice. Try again."
            Start-Sleep -milliseconds 750
            Clear-Host
            continue
        }

        Clear-Host
        Write-Host ''
        # $certs[$result].Thumbprint
        Set-AuthenticodeSignature -FilePath $Path -Certificate $certs[$result]
        return

    } While ($True)
}

switch ($PSCmdlet.ParameterSetName) {
    'Thumbprint' {
        $cert = Get-ChildItem $certStorePath | Where-Object { $_.Thumbprint -eq $Thumbprint };
        if ($null -eq $cert) {
            throw [System..Cert] "Certificate with thumbprint `"$Thumbprint`" not found."
        }
    }
    'SerialNumber' {
        $cert = Get-ChildItem $certStorePath | Where-Object { $_.SerialNumber -eq $SerialNumber };
        if ($null -eq $cert) {
            throw [System..Cert] "Certificate with serialnumber `"$SerialNumber`" not found."
        }
    }
}

Set-AuthenticodeSignature -FilePath $Path -Certificate $cert -HashAlgorithm $HasAlgorithm