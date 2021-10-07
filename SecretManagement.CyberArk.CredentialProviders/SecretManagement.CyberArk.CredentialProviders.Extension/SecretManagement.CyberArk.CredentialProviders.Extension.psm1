#Requires -Module CredentialRetriever

function Get-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    return (Invoke-GetCCPCredential -Name $Name -VaultName $VaultName -AdditionalParameters $AdditionalParameters).ToSecureString()
}

function Get-SecretInfo {
    [CmdletBinding()]
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $Credential = Invoke-GetCCPCredential -Name $Filter -VaultName $VaultName -AdditionalParameters $AdditionalParameters

    $Metadata = [Ordered]@{}
    $Credential.psobject.properties | Where-Object {$PSItem.Name -ne 'Content'} | ForEach-Object { $Metadata[$PSItem.Name] = $PSItem.Value }

    return [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
        "$($Credential.name)", # Name of secret
        [Microsoft.PowerShell.SecretManagement.SecretType]::SecureString, # Secret data type [Microsoft.PowerShell.SecretManagement.SecretType]
        $VaultName, # Name of vault
        $Metadata)  # Optional Metadata parameter
}

function Remove-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    throw 'Not implemented! This functionality is unsupported by Central Central Provider.'
}

function Set-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [object] $Secret,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    throw 'Not implemented! This functionality is unsupported by Central Central Provider.'
}

function Test-SecretVault {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    try {
        Invoke-GetCCPCredential -Name * -VaultName $VaultName -AdditionalParameters $AdditionalParameters -ErrorAction Stop
    } catch {
        $CyberArkErrorCode = $Error[0].FullyQualifiedErrorId.Split(',')[0]
        Write-Host "test $CyberArkErrorCode"
        if ($CyberArkErrorCode -eq 'APPAP229E') {
            Write-Host "Got error code $CyberArkErrorCode : Too many objects. Successful connection to Vault!"
            return $true
        }
        return $false
    }
}

function Invoke-GetCCPCredential {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $VaultParameters = (Get-SecretVault -Name $VaultName).VaultParameters

    $GetCCPCredentialParameters = @{}
    $GetCCPCredentialParameters.Add('AppID', $VaultParameters.AppID)
    $GetCCPCredentialParameters.Add('URL', $VaultParameters.URL)
    $GetCCPCredentialParameters.Add('Object', $Name)
    if ($VaultParameters.SkipCertificateCheck) { $GetCCPCredentialParameters.Add('SkipCertificateCheck', $VaultParameters.SkipCertificateCheck) }
    if ($VaultParameters.UseDefaultCredentials) { $GetCCPCredentialParameters.Add('UseDefaultCredentials', $VaultParameters.UseDefaultCredentials) }
    if ($VaultParameters.Credential) { $GetCCPCredentialParameters.Add('Credential', $VaultParameters.Credential) }
    if ($VaultParameters.CertificateThumbPrint) { $GetCCPCredentialParameters.Add('CertificateThumbPrint', $VaultParameters.CertificateThumbPrint) }
    if ($VaultParameters.Certificate) { $GetCCPCredentialParameters.Add('Certificate', $VaultParameters.Certificatel) }


    try{
        $Credential = Get-CCPCredential @GetCCPCredentialParameters -ErrorAction Stop }
        catch {
            throw $Error[0]
        }

    return $Credential
}