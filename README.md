# SecretManagement.CyberArk.CredentialProviders

## Registering the Vault

````powershell
Register-SecretVault -Name 'Production' -ModuleName SecretManagement.CyberArk.CredentialProviders -VaultParameters @{
    URL = 'https://prod-ccp/'
    AppID = 'windowsScript'
    SkipCertificateCheck = $true
}
````
