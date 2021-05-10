@{
    ModuleVersion = '0.1'
    RootModule = 'SecretManagement.CyberArk.CredentialProviders.Extension.psm1'
    FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault')
}