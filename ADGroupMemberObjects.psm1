function Get-ADGroupMemberObjects {
    [CmdletBinding(ConfirmImpact = 'Low')]
    param(
        [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        [string]$GroupNTAccount
    )

    $GroupDomain = $GroupNTAccount.Split("\") | Select-Object -First 1
    $GroupName = $GroupNTAccount.Split("\") | Select-Object -Last 1
    $GroupDomainController = (Get-ADDomainController -Discover -Domain $GroupDomain -ErrorAction SilentlyContinue).HostName | Select-Object -First 1

    if (!$GroupDomainController) {
        throw "Domain Controller Discovering Error in [$($GroupDomain)]."
    }

    try {
        $GroupDN = Get-ADGroup -Server $GroupDomainController $GroupName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty distinguishedName
    }
    catch {
        throw "Group [$($GroupName)] is not found in [$($GroupDomain)]."
    }
    
    $ADGroupMemberObjects = (Get-ADObject -Server $GroupDomainController $GroupDN -Properties member).member | Get-ADObject -Server $GroupDomainController -Properties ObjectClass, objectSid | Where-Object -Property ObjectClass -in ("user", "foreignSecurityPrincipal") 
    $ADGroupMemberObjectsResult = @()

    ForEach ($ADGroupMemberObject in $ADGroupMemberObjects) {
        try {
            $NTAccount = (New-Object Security.Principal.SecurityIdentifier $ADGroupMemberObject.objectSid).translate( [Security.Principal.NTAccount] ).ToString()
        }
        catch {
            continue
        }
        $Domain = $NTAccount.Split("\") | Select-Object -First 1
        $DomainController = (Get-ADDomainController -Discover -Domain $Domain -ErrorAction SilentlyContinue).HostName | Select-Object -First 1
        if ($DomainController) {
            try {
                $ADObjectUser = Get-ADUser -Server $DomainController $ADGroupMemberObject.objectSid -Properties DisplayName, Department, Manager
            }
            catch {
                $ADObjectUser = $null
            }

            if ($ADObjectUser) {
                try {
                    $ADObjectManager = Get-ADUser -Server $DomainController $ADObjectUser.Manager -Properties DisplayName
                }
                catch {
                    $ADObjectManager = $null
                }
                $ADGroupMemberObjectsResult += New-Object -TypeName PSObject -Property @{
                    NTAccount   = $NTAccount
                    DisplayName = $ADObjectUser.DisplayName
                    Department  = $ADObjectUser.Department
                    Manager     = $ADObjectManager.DisplayName
                }
            }
        }
    }

    return $ADGroupMemberObjectsResult | Select-object -Property NTAccount, DisplayName, Department, Manager
}

function Export-ADGroupMemberObjects {
    [CmdletBinding(ConfirmImpact = 'Low')]
    param(
        [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        [string]$GroupNTAccount,
        [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        [string]$FileName
    )
    
    $ADGroupMemberObjects = Get-ADGroupMemberObjects -GroupNTAccount $GroupNTAccount
    $ADGroupMemberObjects | Export-Csv $FileName -NoTypeInformation -Encoding "UTF8"
    $ADGroupMemberObjects
}

$GroupNTAccountArgumentCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    
    $wordToComplete = $wordToComplete.Replace("'", "")
    
    if ($wordToComplete -Match "\\") {
        $GroupDomain = $wordToComplete.Split("\").ToUpper() | Select-Object -First 1
    }
    else {
        $GroupDomain = (Get-ADDomain).NetBIOSName
    }
    
    $GroupName = $wordToComplete.Split("\") | Select-Object -Last 1
    $GroupDomainController = (Get-ADDomainController -Discover -Domain $GroupDomain).HostName | Select-Object -First 1
    $groups = Get-ADGroup -Server $GroupDomainController -Filter "Name -like '$GroupName*'"
    $groups | ForEach-Object {
        New-Object -Type System.Management.Automation.CompletionResult -ArgumentList "'$GroupDomain\$($_.Name)'",
        $_.Name,
        "ParameterValue",
        $_.Name
    }
}

Register-ArgumentCompleter -CommandName Get-ADGroupMemberObjects -ParameterName GroupNTAccount -ScriptBlock $GroupNTAccountArgumentCompleter
Register-ArgumentCompleter -CommandName Export-ADGroupMemberObjects -ParameterName GroupNTAccount -ScriptBlock $GroupNTAccountArgumentCompleter
Export-ModuleMember -Function @('Get-ADGroupMemberObjects')
Export-ModuleMember -Function @('Export-ADGroupMemberObjects')