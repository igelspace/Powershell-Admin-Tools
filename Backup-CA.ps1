#region Params
[CmdletBinding(DefaultParameterSetName = 'PasswordFile')]

Param(
    [Parameter(Mandatory = $false, ParameterSetName = 'SecurePassword')]
    [Parameter(Mandatory = $true, ParameterSetName = 'RestoreWithSecurePassword')]
    [securestring]
    $SecurePassword,

    [Parameter(Mandatory = $true, ParameterSetName = 'Password')]
    [Parameter(Mandatory = $true, ParameterSetName = 'SavePassword')]
    [Parameter(Mandatory = $true, ParameterSetName = 'RestoreWithPassword')]
    [string]
    $Password,
    
    [Parameter(Mandatory = $true, ParameterSetName = 'PasswordFile')]
    [Parameter(Mandatory = $true, ParameterSetName = 'SavePassword')]
    [Parameter(Mandatory = $true, ParameterSetName = 'RestoreWithPasswordFile')]
    [string]
    $PasswordFile,
    
    [Parameter(Mandatory = $true, ParameterSetName = 'SavePassword')]
    [switch] $SaveSecurePasswordString = $false,
    
    [Parameter(Mandatory = $false, ParameterSetName = 'SecurePassword')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Password')]
    [Parameter(Mandatory = $false, ParameterSetName = 'PasswordFile')]
    [Parameter(Mandatory = $true, ParameterSetName = 'RestoreWithSecurePassword')]
    [Parameter(Mandatory = $true, ParameterSetName = 'RestoreWithPassword')]
    [Parameter(Mandatory = $true, ParameterSetName = 'RestoreWithPasswordFile')]
    [string] $BackupPath = "D:\Backup\CA-Backup",

    [Parameter(Mandatory = $false, ParameterSetName = 'Password')]
    [Parameter(Mandatory = $false, ParameterSetName = 'SecurePassword')]
    [Parameter(Mandatory = $false, ParameterSetName = 'PasswordFile')]
    [int] $Retention = 180,

    [Parameter(Mandatory = $false, ParameterSetName = 'Password')]
    [Parameter(Mandatory = $false, ParameterSetName = 'SecurePassword')]
    [Parameter(Mandatory = $false, ParameterSetName = 'PasswordFile')]
    [switch] $SkipCleanup = $false,

    [Parameter(Mandatory = $false, ParameterSetName = 'Help')]
    [switch] $Help = $false,

    [Parameter(Mandatory = $true, ParameterSetName = 'RestoreWithSecurePassword')]
    [Parameter(Mandatory = $true, ParameterSetName = 'RestoreWithPassword')]
    [Parameter(Mandatory = $true, ParameterSetName = 'RestoreWithPasswordFile')]
    [switch] $Restore = $false,

    [Parameter(Mandatory = $false, ParameterSetName = 'Password')]
    [Parameter(Mandatory = $false, ParameterSetName = 'SecurePassword')]
    [Parameter(Mandatory = $false, ParameterSetName = 'PasswordFile')]
    [Parameter(Mandatory = $false, ParameterSetName = 'RestoreWithSecurePassword')]
    [Parameter(Mandatory = $false, ParameterSetName = 'RestoreWithPassword')]
    [Parameter(Mandatory = $false, ParameterSetName = 'RestoreWithPasswordFile')]
    [switch] $SkipRegistry = $false,

    [Parameter(Mandatory = $false, ParameterSetName = 'Password')]
    [Parameter(Mandatory = $false, ParameterSetName = 'SecurePassword')]
    [Parameter(Mandatory = $false, ParameterSetName = 'PasswordFile')]
    [Parameter(Mandatory = $false, ParameterSetName = 'RestoreWithSecurePassword')]
    [Parameter(Mandatory = $false, ParameterSetName = 'RestoreWithPassword')]
    [Parameter(Mandatory = $false, ParameterSetName = 'RestoreWithPasswordFile')]
    [switch] $SkipCertEnroll = $false,

    [Parameter(Mandatory = $false, ParameterSetName = 'Password')]
    [Parameter(Mandatory = $false, ParameterSetName = 'SecurePassword')]
    [Parameter(Mandatory = $false, ParameterSetName = 'PasswordFile')]
    [Parameter(Mandatory = $false, ParameterSetName = 'RestoreWithSecurePassword')]
    [Parameter(Mandatory = $false, ParameterSetName = 'RestoreWithPassword')]
    [Parameter(Mandatory = $false, ParameterSetName = 'RestoreWithPasswordFile')]
    [switch] $SkipCAPolicy = $false,

    [Parameter(Mandatory = $false, ParameterSetName = 'Password')]
    [Parameter(Mandatory = $false, ParameterSetName = 'SecurePassword')]
    [Parameter(Mandatory = $false, ParameterSetName = 'PasswordFile')]
    [Parameter(Mandatory = $false, ParameterSetName = 'RestoreWithSecurePassword')]
    [Parameter(Mandatory = $false, ParameterSetName = 'RestoreWithPassword')]
    [Parameter(Mandatory = $false, ParameterSetName = 'RestoreWithPasswordFile')]
    [switch] $SkipTemplates = $false
)
#endregion

#region Help
if ($PSCmdlet.ParameterSetName -eq 'Help') {
    Write-Host ''
    Write-Host '##########################################' -ForegroundColor Cyan
    Write-Host '#####                                #####' -ForegroundColor Cyan
    Write-Host '#####    Help for "Backup-CA.ps1"    #####' -ForegroundColor Cyan
    Write-Host '#####                                #####' -ForegroundColor Cyan
    Write-Host '##########################################' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '# Syntax' -ForegroundColor Cyan
    Write-Host '    .\Backup-CA.ps1 ' -ForegroundColor Yellow
    Write-Host '        -Password <string>' -ForegroundColor Blue
    Write-Host '        -PasswordFile <string>' -ForegroundColor Blue
    Write-Host '        -SaveSecurePasswordString' -ForegroundColor Blue
    Write-Host ''
    Write-Host '    .\Backup-CA.ps1 ' -ForegroundColor Yellow
    Write-Host '        -Password <string>' -ForegroundColor Blue
    Write-Host '        [-BackupPath <string>]' -ForegroundColor White
    Write-Host '        [-Retention <int>]' -ForegroundColor White
    Write-Host '        [-SkipCleanup]' -ForegroundColor White
    Write-Host '        [-SkipRegistry]' -ForegroundColor White
    Write-Host '        [-SkipCertEnroll]' -ForegroundColor White
    Write-Host '        [-SkipCAPolicy]' -ForegroundColor White
    Write-Host '        [-SkipTemplates]' -ForegroundColor White
    Write-Host ''
    Write-Host '    .\Backup-CA.ps1 ' -ForegroundColor Yellow
    Write-Host '        -SecurePassword <securestring>' -ForegroundColor Blue
    Write-Host '        [-BackupPath <string>]' -ForegroundColor White
    Write-Host '        [-Retention <int>]' -ForegroundColor White
    Write-Host '        [-SkipCleanup]' -ForegroundColor White
    Write-Host '        [-SkipRegistry]' -ForegroundColor White
    Write-Host '        [-SkipCertEnroll]' -ForegroundColor White
    Write-Host '        [-SkipCAPolicy]' -ForegroundColor White
    Write-Host '        [-SkipTemplates]' -ForegroundColor White
    Write-Host ''
    Write-Host '    .\Backup-CA.ps1 ' -ForegroundColor Yellow
    Write-Host '        -PasswordFile <string>' -ForegroundColor Blue
    Write-Host '        [-BackupPath <string>]' -ForegroundColor White
    Write-Host '        [-Retention <int>]' -ForegroundColor White
    Write-Host '        [-SkipCleanup]' -ForegroundColor White
    Write-Host '        [-SkipRegistry]' -ForegroundColor White
    Write-Host '        [-SkipCertEnroll]' -ForegroundColor White
    Write-Host '        [-SkipCAPolicy]' -ForegroundColor White
    Write-Host '        [-SkipTemplates]' -ForegroundColor White
    Write-Host ''
    Write-Host '    .\Backup-CA.ps1 ' -ForegroundColor Yellow
    Write-Host '        -Password <string>' -ForegroundColor Blue
    Write-Host '        -BackupPath <string>' -ForegroundColor Blue
    Write-Host '        -Restore' -ForegroundColor Blue
    Write-Host '        [-SkipRegistry]' -ForegroundColor White
    Write-Host '        [-SkipCertEnroll]' -ForegroundColor White
    Write-Host '        [-SkipCAPolicy]' -ForegroundColor White
    Write-Host '        [-SkipTemplates]' -ForegroundColor White
    Write-Host ''
    Write-Host '    .\Backup-CA.ps1 ' -ForegroundColor Yellow
    Write-Host '        -SecurePassword <string>' -ForegroundColor Blue
    Write-Host '        -BackupPath <string>' -ForegroundColor Blue
    Write-Host '        -Restore' -ForegroundColor Blue
    Write-Host '        [-SkipRegistry]' -ForegroundColor White
    Write-Host '        [-SkipCertEnroll]' -ForegroundColor White
    Write-Host '        [-SkipCAPolicy]' -ForegroundColor White
    Write-Host '        [-SkipTemplates]' -ForegroundColor White
    Write-Host ''
    Write-Host '    .\Backup-CA.ps1 ' -ForegroundColor Yellow
    Write-Host '        -PasswordFile <string>' -ForegroundColor Blue
    Write-Host '        -BackupPath <string>' -ForegroundColor Blue
    Write-Host '        -Restore' -ForegroundColor Blue
    Write-Host '        [-SkipRegistry]' -ForegroundColor White
    Write-Host '        [-SkipCertEnroll]' -ForegroundColor White
    Write-Host '        [-SkipCAPolicy]' -ForegroundColor White
    Write-Host '        [-SkipTemplates]' -ForegroundColor White
    Write-Host ''
    Write-Host '    .\Backup-CA.ps1 ' -ForegroundColor Yellow
    Write-Host '        -Help' -ForegroundColor Blue
    Write-Host ''
    Write-Host '# Examples' -ForegroundColor Cyan
    Write-Host '    .\Backup-CA.ps1 ' -ForegroundColor Yellow -NoNewline
    Write-Host '-Password ' -ForegroundColor DarkGray  -NoNewline
    Write-Host '"Kennwort1" ' -ForegroundColor Blue -NoNewline
    Write-Host '-PasswordFile ' -ForegroundColor DarkGray -NoNewline
    Write-Host '"C:\backupPW.txt" '-ForegroundColor Blue -NoNewline
    Write-Host '-SaveSecurePasswordString' -ForegroundColor DarkGray 
    Write-Host '    Saves the password "Kennwort1" as a secure string to the path "C:\backupPW.txt" for later use'
    Write-Host ''
    Write-Host '    .\Backup-CA.ps1 ' -ForegroundColor Yellow -NoNewline
    Write-Host '-Password ' -ForegroundColor DarkGray  -NoNewline
    Write-Host '"Kennwort1" ' -ForegroundColor Blue -NoNewline
    Write-Host '-BackupPath ' -ForegroundColor DarkGray  -NoNewline
    Write-Host '"D:\Backup\CA-Backup" ' -ForegroundColor Blue -NoNewline
    Write-Host '-Retention ' -ForegroundColor DarkGray  -NoNewline
    Write-Host '180' -ForegroundColor White
    Write-Host '    Backs up the CA to the path "D:\Backup\CA-Backup" with the password "Kennwort1" and cleans up backups older then 180 days'
    Write-Host ''
    Write-Host '    .\Backup-CA.ps1 ' -ForegroundColor Yellow -NoNewline
    Write-Host '-PasswordFile ' -ForegroundColor DarkGray  -NoNewline
    Write-Host '"C:\backupPW.txt" ' -ForegroundColor Blue -NoNewline
    Write-Host '-BackupPath ' -ForegroundColor DarkGray  -NoNewline
    Write-Host '"D:\Backup\CA-Backup" ' -ForegroundColor Blue -NoNewline
    Write-Host '-Retention ' -ForegroundColor DarkGray  -NoNewline
    Write-Host '180' -ForegroundColor White
    Write-Host '    Backs up the CA to the path "D:\Backup\CA-Backup" with the password stored in the file "C:\backupPW.txt" and cleans up backups older then 180 days'
    Write-Host ''
    Write-Host '    .\Backup-CA.ps1 ' -ForegroundColor Yellow -NoNewline
    Write-Host '-PasswordFile ' -ForegroundColor DarkGray  -NoNewline
    Write-Host '"C:\backupPW.txt" ' -ForegroundColor Blue -NoNewline
    Write-Host '-BackupPath ' -ForegroundColor DarkGray  -NoNewline
    Write-Host '"D:\Backup\CA-Backup" ' -ForegroundColor Blue -NoNewline
    Write-Host '-SkipCleanup' -ForegroundColor DarkGray
    Write-Host '    Backs up the CA to the path "D:\Backup\CA-Backup" with the password stored in the file "C:\backupPW.txt" without cleaning up old backups'
    Write-Host ''
    Write-Host '    .\Backup-CA.ps1 ' -ForegroundColor Yellow -NoNewline
    Write-Host '-PasswordFile ' -ForegroundColor DarkGray  -NoNewline
    Write-Host '"C:\backupPW.txt" ' -ForegroundColor Blue -NoNewline
    Write-Host '-BackupPath ' -ForegroundColor DarkGray  -NoNewline
    Write-Host "`"D:\Backup\CA-Backup\$(Get-Date -Format yyyy-dd-MM-HH-mm)`" " -ForegroundColor Blue -NoNewline
    Write-Host '-Restore' -ForegroundColor DarkGray
    Write-Host "    Restores the CA from the backup at `"D:\Backup\CA-Backup\$(Get-Date -Format yyyy-dd-MM-HH-mm)`" with the password stored in the file `"C:\backupPW.txt`" including starting and stopping the ca service"
    Write-Host ''
    Write-Host '# Parameters' -ForegroundColor Cyan
    Write-Host '    -BackupPath [Path to store the backup]' -ForegroundColor Green
    Write-Host '        The root path for storing backups. The actual path is appended by the current date and time'
    Write-Host '        Example: -Path "D:\Backup\CA-Backup"'
    Write-Host "        Complete path: `"D:\Backup\CA-Backup\`"$(Get-Date -Format yyyy-dd-MM-HH-mm)" 
    Write-Host '        Defaults to "D:\Backup\CA-Backup"'
    Write-Host ''
    Write-Host '    -Help' -ForegroundColor Green
    Write-Host '        Displays this help page'
    Write-Host ''
    Write-Host '    -Password [Password]' -ForegroundColor Green
    Write-Host '        The password for the backup or for storage storage as a secure string.'
    Write-Host ''
    Write-Host '    -PasswordFile [Path to password file]' -ForegroundColor Green
    Write-Host '        The Path to the file containing the secure string with the password for the backup. Also the storage location for creating a new secure string password file'
    Write-Host ''
    Write-Host '    -Restore' -ForegroundColor Green
    Write-Host '        Flag if the script should restore the specified backup'
    Write-Host ''
    Write-Host '    -Retention [Retention time of backups in days]' -ForegroundColor Green
    Write-Host '        Time in days old backups are kept before deletion by the script'
    Write-Host '        Defaults to 180'
    Write-Host ''
    Write-Host '    -SaveSecurePasswordString' -ForegroundColor Green
    Write-Host '        Flag if the password provided should be saved as a secure string at the location provided'
    Write-Host ''
    Write-Host '    -SecurePassword [Password as secure string]' -ForegroundColor Green
    Write-Host '        The password for the backup as a secure string'
    Write-Host ''
    Write-Host '    -SkipCleanup' -ForegroundColor Green
    Write-Host '        Flag for skipping cleanup of old backups'
    Write-Host '    -SkipRegistry' -ForegroundColor Green
    Write-Host '        Flag for skipping backup / restore of CA registry intries'
    Write-Host ''
    Write-Host '    -SkipCertEnroll' -ForegroundColor Green
    Write-Host '        Flag for skipping backup / restore of CertEntroll folder'
    Write-Host ''
    Write-Host '    -SkipCAPolicy' -ForegroundColor Green
    Write-Host '        Flag for skipping backup / restore of CAPolicy.inf'
    Write-Host ''
    Write-Host '    -SkipTemplates' -ForegroundColor Green
    Write-Host '        Flag for skipping backup / restore of published templates'
    Write-Host ''
    Write-Host ''

    exit
}
#endregion

#region Save password as secure string
if ($PSCmdlet.ParameterSetName -eq 'SavePassword') {
    try {
        if (-not $(Test-Path $PasswordFile)) { New-Item -Path $PasswordFile -ItemType File -Force | Out-Null }
    
        $Password | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File $PasswordFile
    }
    catch {
        Write-Host "Something went wrong saving password file" -ForegroundColor Red
        Write-Host $_ -ForegroundColor Red
    }
}
#endregion

#region Backup CA
elseif (
    $PSCmdlet.ParameterSetName -ne 'RestoreWithSecurePassword' -and
    $PSCmdlet.ParameterSetName -ne 'RestoreWithPassword' -and
    $PSCmdlet.ParameterSetName -ne 'RestoreWithPasswordFile'
) {
    try {
        # Prepare path variables
        $date = Get-Date -Format yyyy-dd-MM-HH-mm
        $datum = ((Get-Date).AddDays(-$Retention))
        $DatePath = Join-Path -Path $BackupPath -ChildPath $date
            
        # Create path if not exist
        if (-not $(Test-Path $DatePath)) { New-Item -Path $DatePath -ItemType Directory -Force | Out-Null }
            
        # Prepare password
        switch ($PSCmdlet.ParameterSetName) {
            'SecurePassword' {
                $backupPassword = $SecurePassword
            }
            'PasswordFile' {
                if (-not $(Test-Path $PasswordFile)) { throw [System.IO.FileNotFoundException] "Path to password file `"$PasswordFile`" not found" }
                $backupPassword = Get-Content $PasswordFile | ConvertTo-SecureString
            }
            'Password' {
                $backupPassword = ConvertTo-SecureString $Password -AsPlainText -Force
            }
        }
        
        # Backup actual ca
        Write-Host "Backing up CA" -ForegroundColor Green
        Backup-CARoleService -Path $DatePath -Password $backupPassword -Force

        if ($false -eq $SkipRegistry) {
            Write-Host "Backing up relevant registry entries" -ForegroundColor Green
            $registryResult = Invoke-Command { reg export "HKLM\System\CurrentControlSet\Services\CertSvc" "$DatePath\CertSvc.reg" }
            if ($registryResult -ne "The operation completed successfully.") {
                Write-Host "Error backing up registry entries" -ForegroundColor Red
            }
        }
        else {
            Write-Host "Skipping registry backup" -ForegroundColor Cyan
        }

        if ($false -eq $SkipCAPolicy) {
            Write-Host "Backing up CAPolicy.inf" -ForegroundColor Green
            if (Test-Path -Path 'C:\Windows\CAPolicy.inf') {
                Copy-Item -Path 'C:\Windows\CAPolicy.inf' -Destination "$DatePath\CAPolicy.inf"
            }
            else {
                Write-Host "No CAPolicy.inf found" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "Skipping CAPolicy.inf backup" -ForegroundColor Cyan
        }
        
        if ($false -eq $SkipCertEnroll) {
            Write-Host "Backing up CertEnroll" -ForegroundColor Green
            Copy-Item -Path 'C:\Windows\System32\CertSrv\CertEnroll' -Destination "$DatePath\CertEnroll" -Recurse
        }
        else {
            Write-Host "Skipping CertEnroll backup" -ForegroundColor Cyan
        }
        
        if ($false -eq $SkipTemplates) {
            Write-Host "Backing up issued templates" -ForegroundColor Green
            Get-CATemplate | Foreach-Object { $_.Name } | Out-File -FilePath "$DatePath\CATemplates.txt" -Encoding String -Force
        }
        else {
            Write-Host "Skipping template backup" -ForegroundColor Cyan
        }

        Write-Host "Backup successfull" -ForegroundColor Green        
        Write-Host "Backup location: $DatePath" -ForegroundColor Green
    }
    catch {
        Write-Host "Something went wrong with backing up the CA." -ForegroundColor Red
        Write-Host $_ -ForegroundColor Red
        Write-Host "Deleting empty backup folder" -ForegroundColor Red
        Remove-Item -Path $DatePath -Force -Recurse
    }            
        
    try {
        if ($false -eq $SkipCleanup) {
            # Cleanup old
            Get-ChildItem -Path $BackupPath -Recurse | Where-Object { $_.LastWriteTime -lt $datum } | Remove-Item -Force -Recurse
        }
    }
    catch {
        Write-Host "Something went wrong removing old backups" -ForegroundColor Red
    }  
}
#endregion

#region Restore CA
elseif (
    $PSCmdlet.ParameterSetName -eq 'RestoreWithSecurePassword' -or
    $PSCmdlet.ParameterSetName -eq 'RestoreWithPassword' -or
    $PSCmdlet.ParameterSetName -eq 'RestoreWithPasswordFile'
) {
    try {
        $ExtentionsPath = Join-Path $BackupPath -ChildPath "Extentions"
        if (-not $(Test-Path $ExtentionsPath)) { New-Item -Path $ExtentionsPath -ItemType Directory -Force | Out-Null }

        if (-not $(Test-Path $BackupPath)) { throw [System.IO.FileNotFoundException] "Path to backup location `"$BackupPath`" not found" }

        switch ($PSCmdlet.ParameterSetName) {
            'RestoreWithSecurePassword' {
                $backupPassword = $SecurePassword
            }
            'RestoreWithPasswordFile' {
                if (-not $(Test-Path $PasswordFile)) { throw [System.IO.FileNotFoundException] "Path to password file `"$PasswordFile`" not found" }
                $backupPassword = Get-Content $PasswordFile | ConvertTo-SecureString
            }
            'RestoreWithPassword' {
                $backupPassword = ConvertTo-SecureString $Password -AsPlainText -Force
            }
        }

        Write-Host "Stopping CA service" -ForegroundColor Green
        Stop-Service certsvc

        if ($false -eq $SkipRegistry) {
            Write-Host "Restoring registry from backup" -ForegroundColor Green
            # Import-Registry -Path "$BackupPath\CertSvc.reg"
            if (Test-Path "$BackupPath\CertSvc.reg") {
                # $registryResult = Invoke-Command { reg import "$BackupPath\CertSvc.reg" }
                try {
                    regedit /s "$BackupPath\CertSvc.reg"
                }
                catch{
                    Write-Host "Error restoring registry entries" -ForegroundColor Red
                }
                # if ($registryResult -ne "The operation completed successfully.") {
                # }
            }
            else {
                Write-Host "No registry backup found" -ForegroundColor Red
            }
        }
        else {
            Write-Host "Skipping registry restore" -ForegroundColor Cyan
        }

        if ($false -eq $SkipCertEnroll) {
            Write-Host "Restoring CertEnroll from backup" -ForegroundColor Green
            Copy-Item -Path "$BackupPath\CertEnroll" -Destination 'C:\Windows\System32\CertSrv\' -Recurse -Force
        }
        else {
            Write-Host "Skipping CertEnroll restore" -ForegroundColor Cyan
        }

        if ($false -eq $SkipCAPolicy) {
            if (Test-Path "$BackupPath\CAPolicy.inf") {
                Write-Host "Restoring CAPolicy.inf from backup" -ForegroundColor Green
                Copy-Item -Path "$BackupPath\CAPolicy.inf" -Destination 'C:\Windows\CAPolicy.inf' -Recurse -Force
            }
            else {
                Write-Host "No CAPolicy.inf found" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "Skipping CAPolicy.inf restore" -ForegroundColor Cyan
        }
        
        Write-Host "Restoring CA from backup" -ForegroundColor Green
        Restore-CARoleService -Path $BackupPath -Password $backupPassword -Force


        Write-Host "Starting CA service" -ForegroundColor Green
        Start-Service certsvc
    }
    catch {
        Write-Host "Something went wrong restoring the CA backup:" -ForegroundColor Red
        Write-Host $_ -ForegroundColor Red
    } 
}
#endregion
