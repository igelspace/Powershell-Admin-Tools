#region Params
[CmdletBinding(DefaultParameterSetName = 'Thumbprint')]

param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
    [string]
    $Thumbprint,

    [Parameter(Mandatory = $true, ParameterSetName = 'SerialNumber')]
    [string]
    $SerialNumber,

    [Parameter(Mandatory = $false, ParameterSetName = 'Thumbprint')]
    [Parameter(Mandatory = $false, ParameterSetName = 'SerialNumber')]
    [Parameter(Mandatory = $false, ParameterSetName = 'List')]
    [ValidateSet('LocalMachine', 'CurrentUser')]
    [string]
    $Type = 'LocalMachine',

    [Parameter(Mandatory = $false, ParameterSetName = 'Thumbprint')]
    [Parameter(Mandatory = $false, ParameterSetName = 'SerialNumber')]
    [Parameter(Mandatory = $false, ParameterSetName = 'List')]
    [switch] $WhatIf = $false,

    [Parameter(Mandatory = $true, ParameterSetName = 'Help')]
    [switch] $Help = $false,

    
    [Parameter(Mandatory = $true, ParameterSetName = 'List')]
    [switch] $List = $false
)

DynamicParam {
    $storeParamAttribute = New-Object System.Management.Automation.ParameterAttribute
    $storeParamAttribute.Mandatory = $false
    # $storeParamAttribute.ParameterSetName += 'Thumbprint'
    if ($null -eq $Type -or '' -eq $Type) {
        $Type = 'LocalMachine'
    }

    $storeValidateParam = New-Object System.Management.Automation.ValidateSetAttribute @((Get-ChildItem "Cert:\$Type").Name)

    $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
    $attributeCollection.Add($storeParamAttribute)
    $attributeCollection.Add($storeValidateParam)
    
    $storeParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Store', [string], $attributeCollection)

    $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
    $paramDictionary.Add('Store', $storeParam)

    # Return the dictionary
    return $paramDictionary
}
#endregion


process {
    try {
        #region Help
        if ($PSCmdlet.ParameterSetName -eq 'Help') {
            Write-Host ''
            Write-Host '###################################################' -ForegroundColor Cyan
            Write-Host '#####                                         #####' -ForegroundColor Cyan
            Write-Host '#####    Help for "Delete-Certificate.ps1"    #####' -ForegroundColor Cyan
            Write-Host '#####                                         #####' -ForegroundColor Cyan
            Write-Host '###################################################' -ForegroundColor Cyan
            Write-Host ''
            Write-Host '# Syntax' -ForegroundColor Cyan
            Write-Host '    .\Delete-Certificate.ps1 ' -ForegroundColor Yellow
            Write-Host '        -Thumbprint <string>' -ForegroundColor Blue
            Write-Host '        [-Type <string>]' -ForegroundColor White
            Write-Host '        [-Store <string>]' -ForegroundColor White
            Write-Host '        [-WhatIf]' -ForegroundColor White
            Write-Host ''
            Write-Host '    .\Delete-Certificate.ps1 ' -ForegroundColor Yellow
            Write-Host '        -SerialNumber <string>' -ForegroundColor Blue
            Write-Host '        [-Type <string>]' -ForegroundColor White
            Write-Host '        [-Store <string>]' -ForegroundColor White
            Write-Host '        [-WhatIf]' -ForegroundColor White
            Write-Host ''
            Write-Host '    .\Delete-Certificate.ps1 ' -ForegroundColor Yellow
            Write-Host '        [-Type <string>]' -ForegroundColor White
            Write-Host '        [-Store <string>]' -ForegroundColor White
            Write-Host '        -List' -ForegroundColor Blue
            Write-Host ''
            Write-Host '    .\Delete-Certificate.ps1 ' -ForegroundColor Yellow
            Write-Host '        -Help' -ForegroundColor Blue
            Write-Host ''
            Write-Host '# Examples' -ForegroundColor Cyan
            Write-Host '    .\Delete-Certificate.ps1 ' -ForegroundColor Yellow -NoNewline
            Write-Host '-Thumbprint ' -ForegroundColor DarkGray  -NoNewline
            Write-Host '"D2036177133A471764BB5FCB4704AC7DB07A2B3F" ' -ForegroundColor Blue -NoNewline
            Write-Host '-Type ' -ForegroundColor DarkGray -NoNewline
            Write-Host '"LocalMachine" '-ForegroundColor Blue -NoNewline
            Write-Host '-Store ' -ForegroundColor DarkGray -NoNewline
            Write-Host '"My" '-ForegroundColor Blue
            Write-Host '    Deletes the certificate with the thumbprint "D2036177133A471764BB5FCB4704AC7DB07A2B3F" in "Cert:\LocalMachine\My" and the associated keyfile'
            Write-Host ''
            Write-Host '    .\Delete-Certificate.ps1 ' -ForegroundColor Yellow -NoNewline
            Write-Host '-SerialNumber ' -ForegroundColor DarkGray  -NoNewline
            Write-Host '"6f00000010f279346febe99372000000000010" ' -ForegroundColor Blue -NoNewline
            Write-Host '-Type ' -ForegroundColor DarkGray -NoNewline
            Write-Host '"LocalMachine" '-ForegroundColor Blue -NoNewline
            Write-Host '-Store ' -ForegroundColor DarkGray -NoNewline
            Write-Host '"My" '-ForegroundColor Blue
            Write-Host '    Deletes the certificate with the -serialnumber "6f00000010f279346febe99372000000000010" in "Cert:\LocalMachine\My" and the associated keyfile'
            Write-Host ''
            Write-Host '    .\Delete-Certificate.ps1 ' -ForegroundColor Yellow -NoNewline
            Write-Host '-SerialNumber ' -ForegroundColor DarkGray  -NoNewline
            Write-Host '"6f00000010f279346febe99372000000000010" ' -ForegroundColor Blue -NoNewline
            Write-Host '-Type ' -ForegroundColor DarkGray -NoNewline
            Write-Host '"LocalMachine" '-ForegroundColor Blue -NoNewline
            Write-Host '-Store ' -ForegroundColor DarkGray -NoNewline
            Write-Host '"My" '-ForegroundColor Blue -NoNewline
            Write-Host '-WhatIf' -ForegroundColor DarkGray
            Write-Host '    Shows the path to the certificate and keyfile for the certificate with the serialnumber "6f00000010f279346febe99372000000000010" without deleting anything'
            Write-Host ''
            Write-Host '    .\Delete-Certificate.ps1 ' -ForegroundColor Yellow -NoNewline
            Write-Host '-Type ' -ForegroundColor DarkGray -NoNewline
            Write-Host '"LocalMachine" '-ForegroundColor Blue -NoNewline
            Write-Host '-Store ' -ForegroundColor DarkGray -NoNewline
            Write-Host '"My" '-ForegroundColor Blue -NoNewline
            Write-Host '-List' -ForegroundColor DarkGray
            Write-Host '    Lists all certificates in the store "Cert:\LocalMachine\My"'
            Write-Host ''
            Write-Host '# Parameters' -ForegroundColor Cyan
            Write-Host '    -Help' -ForegroundColor Green
            Write-Host '        Displays this help page.'
            Write-Host ''
            Write-Host '    -List' -ForegroundColor Green
            Write-Host '        Lists all certificates in the provided store.'
            Write-Host ''
            Write-Host '    -SerialNumber [SerialNumber of the certificate]' -ForegroundColor Green
            Write-Host '        The serialnumber of the certificate'
            Write-Host ''
            Write-Host '    -Store [Certificate store]' -ForegroundColor Green
            Write-Host '        The store in which the certificate is stored.'
            Write-Host '        Automatically retrieves the existing stores for the type (LocalMachine / CurrentUser) provided. Values can be completed / selected by pressing tab.'
            Write-Host '        Defaults to: My'
            Write-Host ''
            Write-Host '    -Thumbprint [Thumbprint of the certificate]' -ForegroundColor Green
            Write-Host '        The thumbprint of the certificate'
            Write-Host ''
            Write-Host '    -Type [Type of store]' -ForegroundColor Green
            Write-Host '        Parameter for defining the type of store.'
            Write-Host '        Possible values:'
            Write-Host '            LocalMachine' -ForegroundColor DarkGray
            Write-Host '            CurrentUser' -ForegroundColor DarkGray
            Write-Host '        Defaults to: LocalMachine'
            Write-Host ''
            Write-Host '    -WhatIf' -ForegroundColor Green
            Write-Host '        Shows only the paths to the certificate and keyfile for the provided identifier without deleting anything.'
            Write-Host ''
            Write-Host ''
            exit
        }
        #endregion
        
        #region Prepare paths
        if ($null -eq $Store -or '' -eq $Store -or -not $PSBoundParameters.ContainsKey('Store')) {
            $Store = 'My'
        }
        
        $certStorePath = "Cert:\$Type\$Store"

        if ($List) {
            Get-ChildItem $certStorePath | Select-Object Thumbprint, SerialNumber, Subject, FriendlyName | Format-Table
            exit
        }

        if ($PSVersionTable.PSEdition -eq 'Core') {
            Write-Host "You are running PowerShell Core. Please change to PowerShell 5.1" -ForegroundColor Red
            exit
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
                    throw [System..Cert] "Certificate with sertialnumber `"$SerialNumber`" not found."
                }
            }
        }
    
        $keyName = (($cert.PrivateKey).CspKeyContainerInfo).UniqueKeyContainerName
    
        switch ($Type) {
            'LocalMachine' {
                $keyPath = $env:ProgramData + "\Microsoft\Crypto\RSA\MachineKeys\"
            }
            'CurrentUser' {
                $keyPath = $env:APPDATA + "\Microsoft\Crypto\RSA"
            }
        }

        $fullPath = $keyPath + $keyName
        $certPath = Join-Path -Path $certStorePath -ChildPath $cert.Thumbprint
        #endregion

        #region WhatIf
        if ($WhatIf) {
            Write-Host "Certificate to remove: $certPath" -ForegroundColor Cyan
            if ((Test-Path $fullPath) -and ($fullPath -ne $keyPath)) {
                Write-Host "Keyfile to remove:     $fullPath" -ForegroundColor Cyan
            }
            else {
                Write-Host "No associated keyfile found." -ForegroundColor Red
            }
        }
        #endregion

        #region Deletion
        else {
            if (Test-Path $certPath) {
                Remove-Item $certPath -Force
                Write-Host "Successfully removed certificate with thumbprint `"$($cert.Thumbprint)`"." -ForegroundColor Green
            }

            if ((Test-Path $fullPath) -and ($fullPath -ne $keyPath)) {
                Remove-Item $fullPath -Force
                Write-Host "Successfully removed associated keyfile." -ForegroundColor Green
            }
            else {
                Write-Host "No keyfile associated with certificate with thumbprint `"$($cert.Thumbprint)`" found." -ForegroundColor Red
            }
        }
        #endregion
    }
    catch {
        Write-Host 'Something went wrong' -ForegroundColor Red
        $_
    }
}