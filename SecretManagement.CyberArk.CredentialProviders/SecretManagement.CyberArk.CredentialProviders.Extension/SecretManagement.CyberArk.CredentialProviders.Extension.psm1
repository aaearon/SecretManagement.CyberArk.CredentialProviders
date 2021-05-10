function Get-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $VaultParameters = (Get-SecretVault -Name $VaultName).VaultParameters

    $GetCCPCredentialParameters = @{}
    $GetCCPCredentialParameters.Add('AppId', $VaultParameters.AppID)
    $GetCCPCredentialParameters.Add('URL', $VaultParameters.URL)
    $GetCCPCredentialParameters.Add('Object', $Name)
    if ($VaultParameters.SkipCertificateCheck) { $GetCCPCredentialParameters.Add('SkipCertificateCheck', $VaultParameters.SkipCertificateCheck) }
    if ($VaultParameters.UseDefaultCredentials) { $GetCCPCredentialParameters.Add('UseDefaultCredentials', $VaultParameters.UseDefaultCredentials) }
    if ($VaultParameters.Credential) { $GetCCPCredentialParameters.Add('Credential', $VaultParameters.Credential) }
    if ($VaultParameters.CertificateThumbPrint) { $GetCCPCredentialParameters.Add('CertificateThumbPrint', $VaultParameters.CertificateThumbPrint) }
    if ($VaultParameters.Certificate) { $GetCCPCredentialParameters.Add('Certificate', $VaultParameters.Certificatel) }

    $Secret = (Get-CCPCredential @GetCCPCredentialParameters).toSecureString()
    return $Secret
}

function Get-SecretInfo {
    [CmdletBinding()]
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    foreach ($Account in $results) {
        $Metadata = [Ordered]@{}
        $Account.psobject.properties | ForEach-Object { $Metadata[$PSItem.Name] = $PSItem.Value }

        $SecretInfo = [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
            "$($Account.name)", # Name of secret
            [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential, # Secret data type [Microsoft.PowerShell.SecretManagement.SecretType]
            $VaultName, # Name of vault
            $Metadata)  # Optional Metadata parameter)

        $Secrets.Add($SecretInfo)
    }

    return $Secrets
}

function Remove-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    # Not possible with AIM!!!
}

function Set-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [object] $Secret,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    # Not possible with AIM!!!

}

function Test-SecretVault {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )

    # Test-PASSession
    return $true
}