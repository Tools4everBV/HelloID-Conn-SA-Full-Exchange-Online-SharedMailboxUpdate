#######################################################################
# Template: HelloID SA Powershell data source
# Name: shared-mailbox-update-check-mailbox-exists
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

$outputText = [System.Collections.Generic.List[PSCustomObject]]::new()

# global variables (Automation --> Variable libary):
$TenantId = $EntraTenantId
$AppID = $EntraAppID
$Secret = $EntraSecret
$Organization = $EntraOrganization

# variables configured in form:
$Name = $datasource.Name
$currentName = $datasource.SelectedSM.Name
$currentPrimarySmtpAddress = $datasource.SelectedSM.primarySmtpAddress
$currentExchangeGuid = $datasource.SelectedSM.id
$PrimarySmtpAddress = $datasource.PrimarySmtpAddress
$currentAlias = $datasource.SelectedSM.alias
$Alias = $datasource.Alias
$Domain = $PrimarySmtpAddress -Split '@'
$Domain = $Domain[1]

# PowerShell commands to import
$commands = @("Get-User", "Get-Mailbox")
#endregion init

try {
    if (($currentName -eq $Name) -and ($currentPrimarySmtpAddress -eq $PrimarySmtpAddress) -and ($currentAlias -eq $Alias)) {
        $outputText.Add([PSCustomObject]@{
                Message = "Name [$currentName] not changed"
                IsError = $true
            })
        $outputText.Add([PSCustomObject]@{
                Message = "PrimarySmtpAddress [$currentPrimarySmtpAddress] not changed"
                IsError = $true
            })
        $outputText.Add([PSCustomObject]@{
                Message = "Alias [$currentAlias] not changed"
                IsError = $true
            })
    }

    if (-not($outputText.isError -contains - $true)) {
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

        $SharedMailboxParams = @{
            Filter      = "{DisplayName -eq '$Name' -or Name -eq '$Name' -or Alias -eq '$Alias' -or PrimarySmtpAddress -eq '$PrimarySmtpAddress'}"
            ErrorAction = 'Stop'        
        }
    
        $SharedMailboxes = Get-Mailbox @SharedMailboxParams

        if ([string]::IsNullOrEmpty($SharedMailboxes)) {
            Write-Information  "Shared Mailbox [$Name] is available"
            $outputText.Add([PSCustomObject]@{
                    Message = "Shared Mailbox [$Name] is available"
                    IsError = $false
                })
        }     
        else {
            foreach ($record in $SharedMailboxes) {
                if ((($record.Name -eq $Name) -or ($record.DisplayName -eq $Name)) -and ($record.ExchangeGuid -ne $currentExchangeGuid)) {
                    $outputText.Add([PSCustomObject]@{
                            Message = "Name [$Name] not unique, found on [$($record.Name)]"
                            IsError = $true
                        })
                }
                if (($record.Alias -eq $Alias) -and ($record.ExchangeGuid -ne $currentExchangeGuid)) {
                    $outputText.Add([PSCustomObject]@{
                            Message = "Alias [$Alias] not unique, found on [$($record.Name)]"
                            IsError = $true
                        })
                }
                if ((($record.EmailAddresses -eq "SMTP:$PrimarySmtpAddress") -or ($record.ProxyAddresses -eq "smtp:$PrimarySmtpAddress")) -and ($record.ExchangeGuid -ne $currentExchangeGuid)) {
                    $outputText.Add([PSCustomObject]@{
                            Message = "PrimarySmtpAddress [$PrimarySmtpAddress] not unique, found on [$($record.Name)]"
                            IsError = $true
                        })
                }
                elseif (($record.EmailAddresses -eq "SMTP:$Alias@$Domain") -or ($record.ProxyAddresses -eq "smtp:$Alias@$Domain") -and ($record.ExchangeGuid -ne $currentExchangeGuid)) {
                    $outputText.Add([PSCustomObject]@{
                            Message = "ProxyAddress [$Alias@$Domain] not unique, found on [$($record.Name)]"
                            IsError = $true
                        })
                }
            }
        }
        #endregion check shared mailbox           
    }

    if ($outputText.isError -contains - $true) {
        $outputMessage = "Invalid"
    }
    else {
        $outputMessage = "Valid"
        $outputText.Add([PSCustomObject]@{
                Message = "Name [$Name] unique"
                IsError = $false
            })
        $outputText.Add([PSCustomObject]@{
                Message = "Alias [$Alias] unique"
                IsError = $false
            })
        $outputText.Add([PSCustomObject]@{
                Message = "PrimarySmtpAddress [$PrimarySmtpAddress] unique"
                IsError = $false
            })
    }

    foreach ($text in $outputText) {
        $outputMessage += " | " + $($text.Message)
    }

    $returnObject = @{
        text = $outputMessage
    }

    Write-Output $returnObject   
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

    Write-Error "Error $actionMessage for Exchange Online shared mailbox [$Name]. Error: $errorMessage"
    
    $outputMessage = "Invalid | Error $actionMessage for Exchange Online shared mailbox [$Name]. Error: $errorMessage"
    $returnObject = @{
        text = $outputMessage
    }
}
finally {
    Write-Output $returnObject 
}
#endregion lookup
