#region Parameters
[CmdletBinding(DefaultParameterSetName = 'Default')]
param (
    [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
    [string[]]
    $IPs,

    [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
    [string[]]
    $Domains,

    [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
    [string]
    $Rule = '*Remote Desktop - User Mode*',

    [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
    [switch]
    $WhatIf = $false,

    [Parameter(Mandatory = $true, ParameterSetName = 'Help')]
    [switch]
    $Help = $false
)
#endregion

#region Help
if ($PSCmdlet.ParameterSetName -eq 'Help') {
    Write-Host ''
    Write-Host '#####################################################' -ForegroundColor Cyan
    Write-Host '#####                                           #####' -ForegroundColor Cyan
    Write-Host '#####    Help for "Set-RemoteDesktopIPs.ps1"    #####' -ForegroundColor Cyan
    Write-Host '#####                                           #####' -ForegroundColor Cyan
    Write-Host '#################################################ä###' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '# Syntax' -ForegroundColor Cyan
    Write-Host '    .\Set-RemoteDesktopIPs.ps1 ' -ForegroundColor Yellow
    Write-Host '        [-IPs <string[]>]' -ForegroundColor White
    Write-Host '        [-Domains <string[]>]' -ForegroundColor White
    Write-Host '        [-Rule <string>]' -ForegroundColor White
    Write-Host '        [-WhatIf <string>]' -ForegroundColor White
    Write-Host ''
    Write-Host '    .\Set-RemoteDesktopIPs.ps1 ' -ForegroundColor Yellow
    Write-Host '        -Help' -ForegroundColor Blue
    Write-Host ''
    Write-Host '# Examples' -ForegroundColor Cyan
    Write-Host '    .\Set-RemoteDesktopIPs.ps1 ' -ForegroundColor Yellow -NoNewline
    Write-Host '-IPs ' -ForegroundColor DarkGray  -NoNewline
    Write-Host '"8.8.8.8", "1.1.1.1" ' -ForegroundColor Blue -NoNewline
    Write-Host '-Domains ' -ForegroundColor DarkGray -NoNewline
    Write-Host '"google.com"'-ForegroundColor Blue -NoNewline
    Write-Host '    '
    Write-Host ''
    Write-Host '# Parameters' -ForegroundColor Cyan
    Write-Host '    -Domains [List of domains]' -ForegroundColor Green
    Write-Host '        A list of domains for which the script collects the IPs. Those are used added to the IPs for restricting the selected firewall rules'
    Write-Host ''
    Write-Host '    -Help' -ForegroundColor Green
    Write-Host '        Displays this help page'
    Write-Host ''
    Write-Host '    -IPs [List of IPs]' -ForegroundColor Green
    Write-Host '        A list of IPs hich are used for restricting the selected firewall rules'
    Write-Host ''
    Write-Host '    -Rule' -ForegroundColor Green
    Write-Host '        The displayname of the rule for which to add the restriction.  Wildcards can be used to select multiple rules at once'
    Write-Host '        Defaults to: "*Remote Desktop - User Mode*"'
    Write-Host ''
    Write-Host '    -WhatIf' -ForegroundColor Green
    Write-Host '        '
    Write-Host ''
    Write-Host ''
    exit
}
#endregion

#region Parameter Error
if (($null -eq $IPs) -and ($null -eq $Domains)) {
    Write-Host 'Provide either a list of IPs or a list of domains' -ForegroundColor Red
    exit
}
#endregion

#region IP preperation
$ipsToSet = $IPs

foreach ($domain in $Domains) {
    $ip = Resolve-DNSName $domain
    $ipsToSet += $ip.IPAddress
}
#endregion

#region Rule update
$rules = Get-NetFirewallrule -DisplayName $Rule
foreach ($r in $rules) {
    $currentIPs = (Get-NetFirewallRule -Name $r.Name | Get-NetFirewallAddressFilter ).RemoteAddress
    $setIP = $false;

    foreach ($ip in $ipsToSet) {
        if ($currentIPs -ccontains $ip) {
            continue
        }
        $setIP = $true
        break
    }

    foreach ($ip in $currentIPs) {
        if ($ipsToSet -ccontains $ip) {
            continue
        }
        $setIP = $true
        break
    }

    if ($WhatIf) {
        Write-Host 'Rule:        ' -NoNewline -ForegroundColor Cyan
        Write-Host $r.DisplayName 
        Write-Host 'Current IPs: ' -NoNewline -ForegroundColor Cyan
        Write-Host $currentIPs 
        Write-Host 'New IPs:     ' -NoNewline -ForegroundColor Cyan
        Write-Host $ipsToSet 
        Write-Host '-----------------'
    }
    elseif ($setIP) {
        Write-Host "Setting IPs for rule $($r.DisplayName)" -ForegroundColor Cyan
        Write-Host 'New IPs: ' -NoNewline -ForegroundColor Cyan
        Write-Host $ipsToSet 
        Set-NetFirewallRule -DisplayName $r.DisplayName -RemoteAddress $ips
    }
    else {
        Write-Host "IPs already set for rule $($r.DisplayName)"
    }
}
#endregion


