#######################################################################
# Template: HelloID SA Powershell data source
# Name: Shared-mailbox-generate-table-update
# Date: 02-12-2024
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

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
$searchValue = $datasource.searchValue
$searchQuery = "*$searchValue*"

# PowerShell commands to import
$commands = @("Get-User", "Get-Mailbox")
#endregion init

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

    #region check shared mailbox
    $actionMessage = "getting shared mailbox"

    if (-not [String]::IsNullOrEmpty($searchValue)) {
        Write-information "searchQuery: $searchQuery"    
            
        $SharedMailboxParams = @{
            Filter               = "{Alias -like '$searchQuery' -or Name -like '$searchQuery'}"
            RecipientTypeDetails = "SharedMailbox"
            ResultSize           = "Unlimited"
            Verbose              = $false
            ErrorAction          = "Stop"   
        }

        $mailboxes = Get-Mailbox @SharedMailboxParams

        $resultCount = @($mailboxes).Count
        
        Write-Information "Result count: $resultCount"
        
        if ($resultCount -gt 0) {
            foreach ($mailbox in $mailboxes) {
                $returnObject = @{
                    name               = "$($mailbox.displayName)"
                    alias              = "$($mailbox.Alias)"
                    id                 = "$($mailbox.ExchangeGuid)"
                    primarySmtpAddress = "$($mailbox.PrimarySmtpAddress)"
                }

                Write-Output $returnObject
            }
        }
    }
    #endregion check shared mailbox           
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

    Write-Error "Error $actionMessage for Exchange Online shared mailbox with the query [$searchQuery]. Error: $errorMessage"
}
#endregion lookup
