# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form:
$exchangeMailGUID = $form.sharedMailbox.id
$name = $form.name
$alias = $form.alias
$primarySmtpAddress = $form.primarySmtpAddress

# PowerShell commands to import
$commands = @("Get-User", "Set-Mailbox" , "Get-Mailbox")
#endregion init

#region functions

#endregion functions

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#region Import module & connect
try {    
    $actionMessage = "importing module [ExchangeOnlineManagement]"
    $importModuleSplatParams = @{
        Name        = "ExchangeOnlineManagement"
        Cmdlet      = $commands
        Verbose     = $false
        ErrorAction = "Stop"
    }
    $null = Import-Module @importModuleSplatParams

    #region Retrieving certificate
    $actionMessage = "retrieving certificate"
    $certificate = Get-MSEntraCertificate
    #endregion Retrieving certificate
    
    #region Connect to Microsoft Exchange Online
    # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/connect-exchangeonline?view=exchange-ps
    $actionMessage = "connecting to Microsoft Exchange Online"
    $createExchangeSessionSplatParams = @{
        Organization          = $EntraIdOrganization
        AppID                 = $EntraIdAppId
        Certificate           = $certificate
        CommandName           = $commands
        ShowBanner            = $false
        ShowProgress          = $false
        TrackPerformance      = $false
        SkipLoadingCmdletHelp = $true
        SkipLoadingFormatData = $true
        ErrorAction           = "Stop"
    }
    $null = Connect-ExchangeOnline @createExchangeSessionSplatParams
    Write-Information "Connected to Microsoft Exchange Online"
} 
catch {
    $ex = $PSItem
    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)"
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)"        
    }
    else {
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
    }
    Write-Warning $warningMessage
    Write-Error $auditMessage
}



#region get sharedmailbox
try{
    $GetMailboxParams = @{
        Identity    = $exchangeMailGUID
        ErrorAction = 'Stop'
    }

    $mailbox = Get-Mailbox @GetMailboxParams
    $currentAddresses = $mailbox.EmailAddresses
    $proxyAddresses = @()
    foreach ($address in $currentAddresses) {
        if ($address.StartsWith('SMTP:')) {
            $address = $address -replace 'SMTP:', 'smtp:'
        }
        if ($address -ne "smtp:" + $primarySmtpAddress) {
            $proxyAddresses += $address
        }
    }

    $proxyAddresses += 'SMTP:' + $primarySmtpAddress

    #region update shared mailbox
    $actionMessage = "updating shared mailbox"

    $UpdateMailboxParams = @{
        Identity       = $exchangeMailGUID
        DisplayName    = $name
        Name           = $name
        EmailAddresses = $proxyAddresses
        Alias          = $alias
        ErrorAction    = 'Stop'
    }

    Set-Mailbox @UpdateMailboxParams
 
    Write-Information  "Shared Mailbox [$name] updated successfully" 
    $Log = @{
        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
        System            = "Exchange Online" # optional (free format text) 
        Message           = "Shared Mailbox [$name] updated successfully"  # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $name # optional (free format text) 
        TargetIdentifier  = $([string]$exchangeMailGUID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log 
}
catch {
    $ex = $PSItem
    if (-not [string]::IsNullOrEmpty($ex.Exception.Data.RemoteException.Message)) {
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Data.RemoteException.Message)"
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Data.RemoteException.Message)"
    }
    else {
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
    }
   $Log = @{
        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
        System            = "Exchange Online" # optional (free format text) 
        Message           = "Error $actionMessage for Exchange Online shared mailbox [$name]" # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $name # optional (free format text) 
        TargetIdentifier  = $([string]$exchangeMailGUID) # optional (free format text) 
    }
    Write-Information -Tags "Audit" -MessageData $log
    Write-Warning $warningMessage
    Write-Error $auditMessage
    # exit # use when using multiple try/catch and the script must stop
}
