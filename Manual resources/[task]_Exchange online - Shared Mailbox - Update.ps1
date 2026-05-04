# variables configured in form
$mailbox = $form.gridMailbox
$mailboxDisplayName = $form.displayName
$mailboxMailPrefix = $form.mailPrefix
$mailboxMailDomain = $form.mailDomain.id
$blnSetAsPrimaryEmail = [System.Convert]::ToBoolean($form.blnSetAsPrimaryEmail)
# Build proxy address with appropriate prefix based on whether it should be primary
if ($blnSetAsPrimaryEmail) {
   $mailboxProxyAddress = "SMTP:$($mailboxMailPrefix)@$($mailboxMailDomain)"
}
else {
   $mailboxProxyAddress = "smtp:$($mailboxMailPrefix)@$($mailboxMailDomain)"
}
$mailboxAlias = $form.alias

# Global variables
# Outcommented as these are set from Global Variables
# $EntraIdOrganization = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# Fixed values
$commands = @(
   "Set-Mailbox"
)

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

#region functions
function Get-MSEntraCertificate {
   [CmdletBinding()]
   param(
      [Parameter(Mandatory)]
      [ValidateNotNullOrEmpty()]
      [string]
      $CertificateBase64String,
        
      [Parameter(Mandatory)]
      [ValidateNotNullOrEmpty()]
      [string]
      $CertificatePassword
   )
   try {
      $rawCertificate = [system.convert]::FromBase64String($CertificateBase64String)
      $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
      Write-Output $certificate
   }
   catch {
      $PSCmdlet.ThrowTerminatingError($_)
   }
}
#endregion functions

try {
   # Import module
   $actionMessage = "importing module [ExchangeOnlineManagement]"
        
   $importModuleSplatParams = @{
      Name        = "ExchangeOnlineManagement"
      Cmdlet      = $commands
      Verbose     = $false
      ErrorAction = "Stop"
   }

   $null = Import-Module @importModuleSplatParams

   Write-Verbose "Imported module [ExchangeOnlineManagement]"

   # Convert base64 certificate string to certificate object
   $actionMessage = "converting base64 certificate string to certificate object"

   $certificate = Get-MSEntraCertificate -CertificateBase64String $EntraIdCertificateBase64String -CertificatePassword $EntraIdCertificatePassword

   Write-Verbose "Converted base64 certificate string to certificate object"

   # Connect to Microsoft Exchange Online
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

   # Update shared mailbox
   $actionMessage = "updating shared mailbox with ProxyAddress [$($mailboxProxyAddress)]"

   # Get current email addresses and prepare new email address list, while keeping existing proxy addresses (except the current address if already present)
   $currentAddresses = $mailbox.EmailAddresses
   $proxyAddresses = @()
    
   # Extract the email address without prefix for comparison
   $emailAddressOnly = $mailboxProxyAddress -replace '^(smtp|SMTP):', ''
    
   foreach ($address in $currentAddresses) {
      # If setting as primary, convert any existing primary SMTP to secondary
      if ($blnSetAsPrimaryEmail -and $address.StartsWith('SMTP:')) {
         $address = $address -replace 'SMTP:', 'smtp:'
      }
      # Remove the address if it already exists (to avoid duplicates)
      if ($address -ne "smtp:$emailAddressOnly" -and $address -ne "SMTP:$emailAddressOnly") {
         $proxyAddresses += $address
      }
   }
   # Add the new proxy address
   $proxyAddresses += $mailboxProxyAddress

   $UpdateMailboxParams = @{
      Identity       = $mailbox.PrimarySmtpAddress
      Name           = $mailboxDisplayName
      DisplayName    = $mailboxDisplayName
      EmailAddresses = $proxyAddresses
      ErrorAction    = 'Stop'
   }

   # Add Alias if specified
   if (-not [string]::IsNullOrEmpty($mailboxAlias)) {
      $UpdateMailboxParams["Alias"] = $mailboxAlias
   }

   $null = Set-Mailbox @UpdateMailboxParams

   # Send auditlog to HelloID
   $Log = @{
      Action            = "UpdateResource" # optional. ENUM (undefined = default) 
      System            = "ExchangeOnline" # optional (free format text) 
      Message           = "Updated shared mailbox with ProxyAddress [$($mailboxProxyAddress)]"  # required (free format text) 
      IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
      TargetDisplayName = $mailboxDisplayName # optional (free format text) 
      TargetIdentifier  = $emailAddressOnly # optional (free format text) 
   }
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
      System            = "ExchangeOnline" # optional (free format text) 
      Message           = $auditMessage # required (free format text) 
      IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
      TargetDisplayName = $mailbox.DisplayName # optional (free format text) 
      TargetIdentifier  = $mailbox.PrimarySmtpAddress # optional (free format text) 
   }
    
   Write-Information -Tags "Audit" -MessageData $log
   Write-Warning $warningMessage
   Write-Error $auditMessage
}
finally {
   # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/disconnect-exchangeonline?view=exchange-ps
   $deleteExchangeSessionSplatParams = @{
      Confirm     = $false
      ErrorAction = "Stop"
   }
   $null = Disconnect-ExchangeOnline @deleteExchangeSessionSplatParams
}
