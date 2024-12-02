#######################################################################
# Template: HelloID SA Delegated form task
# Name: Exchange Online Shared Mailbox - Update
# Date: 02-12-2024
#######################################################################

# For basic information about delegated form tasks see:
# https://docs.helloid.com/en/service-automation/delegated-forms/delegated-form-powershell-scripts.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable libary):
$TenantId = $EntraTenantId
$AppID = $EntraAppID
$Secret = $EntraSecret
$Organization = $EntraOrganization

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

try {
    #region import module
    $actionMessage = "importing $moduleName module"

    $importModuleParams = @{
        Name        = "ExchangeOnlineManagement"
        Cmdlet      = $commands
        ErrorAction = 'Stop'
    }

    Import-Module @importModuleParams
    #endregion import module

    #region create access token
    Write-Verbose "Creating Access Token"
    $actionMessage = "creating access token"
        
    $body = @{
        grant_type    = "client_credentials"
        client_id     = "$AppID"
        client_secret = "$Secret"
        resource      = "https://outlook.office365.com"
    }

    $exchangeAccessTokenParams = @{
        Method          = 'POST'
        Uri             = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        Body            = $body
        ContentType     = 'application/x-www-form-urlencoded'
        UseBasicParsing = $true
    }
        
    $accessToken = (Invoke-RestMethod @exchangeAccessTokenParams).access_token
    #endregion create access token

    #region connect to Exchange Online
    Write-Verbose "Connecting to Exchange Online"
    $actionMessage = "connecting to Exchange Online"

    $exchangeSessionParams = @{
        Organization     = $Organization
        AppID            = $AppID
        AccessToken      = $accessToken
        CommandName      = $commands
        ShowBanner       = $false
        ShowProgress     = $false
        TrackPerformance = $false
        ErrorAction      = 'Stop'
    }
    Connect-ExchangeOnline @exchangeSessionParams
        
    Write-Information "Successfully connected to Exchange Online"
    #endregion connect to Exchange Online

    #region get sharedmailbox

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
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorMessage = ($ex.ErrorDetails.Message | Convertfrom-json).error_description
    }
    else {
        $errorMessage = $($ex.Exception.message)
    }

    Write-Error "Error $actionMessage for Exchange Online shared mailbox [$name]. Error: $errorMessage"

    $Log = @{
        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
        System            = "Exchange Online" # optional (free format text) 
        Message           = "Error $actionMessage for Exchange Online shared mailbox [$name]" # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $name # optional (free format text) 
        TargetIdentifier  = $([string]$exchangeMailGUID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
