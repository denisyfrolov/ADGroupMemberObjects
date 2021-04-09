function Get-ADGroupMemberObjects {
    [CmdletBinding(ConfirmImpact = 'Low')]
    param(
        [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        [string]$GroupName,
        [string[]]$ObjectClasses = ("user", "contact")
    )

    $GroupDN = Get-ADGroup $GroupName | Select-Object -ExpandProperty distinguishedName

    return (Get-ADObject $GroupDN -Properties member).member | Get-ADObject -Properties ObjectClass, sAMAccountName, DisplayName, Department, Manager | Where-Object -Property ObjectClass -in $ObjectClasses | Select-Object sAMAccountName, DisplayName, Department, @{l = "Manager"; e = { (Get-ADObject $_.Manager -Properties DisplayName).DisplayName } }
}

function Export-ADGroupMemberObjects {
    [CmdletBinding(ConfirmImpact = 'Low')]
    param(
        [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        [string]$GroupName,
        [string[]]$ObjectClasses = ("user", "contact"),
        [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        [string]$FileName
    )
    $ADGroupMemberObjects = Get-ADGroupMemberObjects -GroupName $GroupName -ObjectClasses $ObjectClasses
    $ADGroupMemberObjects | Format-Table sAMAccountName, DisplayName, Department, Manager
    $ADGroupMemberObjects | Export-csv $FileName -NoTypeInformation
}

$GroupNameArgumentCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $groups = Get-ADGroup -Filter "Name -like '$wordToComplete*'"
    $groups | ForEach-Object {
        New-Object -Type System.Management.Automation.CompletionResult -ArgumentList "'$($_.Name)'",
            $_.Name,
            "ParameterValue",
            $_.Name
    }
}

Register-ArgumentCompleter -CommandName Get-ADGroupMemberObjects -ParameterName GroupName -ScriptBlock $GroupNameArgumentCompleter
Register-ArgumentCompleter -CommandName Export-ADGroupMemberObjects -ParameterName GroupName -ScriptBlock $GroupNameArgumentCompleter
Export-ModuleMember -Function @('Get-ADGroupMemberObjects')
Export-ModuleMember -Function @('Export-ADGroupMemberObjects')