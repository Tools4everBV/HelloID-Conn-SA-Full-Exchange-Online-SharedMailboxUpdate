# HelloID-Conn-SA-Full-Exchange-Online-SharedMailboxUpdate

## Description
HelloID-Conn-SA-Full-Exchange-Online-SharedMailboxUpdate is a template for HelloID Service Automation (SA) Delegated Forms. It can be imported into HelloID and customized to your needs.

With this delegated form, you can update a shared mailbox in Exchange Online. The workflow includes:
 1. Enter a search term (alias/name)
 2. Retrieve and select the shared mailbox from the results
 3. Edit Name, Alias, and PrimarySmtpAddress
 4. Validate uniqueness (name/alias/primary SMTP)
 5. Submit the form to apply the update in Exchange Online

Notes shown in the form:
- Retrieving and validating data typically takes ~10 seconds

## Getting started
### Requirements

#### App Registration & Certificate Setup

Before implementing this connector, make sure to configure a Microsoft Entra ID, an App Registration. During the setup process, you’ll create a new App Registration in the Entra portal, assign the necessary API permissions (such as user and group read/write), and generate and assign a certificate.

Follow the official Microsoft documentation for creating an App Registration and setting up certificate-based authentication:
- [App-only authentication with certificate (Exchange Online)](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#set-up-app-only-authentication)

#### HelloID-specific configuration

Once you have completed the Microsoft setup and followed their best practices, configure the following HelloID-specific requirements.

- **API Permissions** (Application permissions):
  - `User.ReadWrite.All`
  - `Group.ReadWrite.All`
  - `GroupMember.ReadWrite.All`
  - `UserAuthenticationMethod.ReadWrite.All`
  - `User.EnableDisableAccount.All`
  - `User-PasswordProfile.ReadWrite.All`
  - `User-Phone.ReadWrite.All`
  - **Entra ID Role assignment:**
  - Assign the **Exchange Recipient Administrator** role to the App Registration
- **Certificate:**
  - Upload the public key file (.cer) in Entra ID
  - Provide the certificate as a Base64 string in HelloID. For instructions on creating the certificate and obtaining the base64 string, refer to our forum post: [Setting up a certificate for Microsoft Graph API in HelloID connectors](https://forum.helloid.com/forum/helloid-provisioning/5338-instruction-setting-up-a-certificate-for-microsoft-graph-api-in-helloid-connectors#post5338)

### Connection settings

The following user-defined variables are used by the connector.

| Setting     | Description                              | Mandatory |
| ----------- | ---------------------------------------- | --------- |
| EntraTenantId | Entra tenant ID                       | Yes       |
| EntraAppId    | Entra application (client) ID         | Yes       |
| EntraCertificateBase64String | Entra Certificate string      | Yes       |
| EntraCertificatePassword | Entra Certificate password      | Yes       |

## Remarks

- **Search data source**:
  - The form includes a search field that retrieves matching shared mailboxes using Exchange Online cmdlets.
  - It lists `Alias`, `Name`, and `PrimarySmtpAddress` using `Get-Mailbox` with `RecipientTypeDetails = SharedMailbox`.
- **Mailbox update**:
  - The delegated form task uses `Set-Mailbox` to update the selected mailbox (`DisplayName`/`Name`, `Alias`, and `PrimarySmtpAddress`). The script rebuilds proxy addresses to set the new primary SMTP.
- **Performance notes**:
  - Retrieval/validation/update typically completes in ~10 seconds; actual times may vary.
- **Duplicate import**:
  - When importing a duplicate form, resource names can be suffixed automatically, as configured in the script.

## Development resources

### API endpoints

This connector uses Exchange Online PowerShell (EXO) cmdlets via the `ExchangeOnlineManagement` module:

| Cmdlet/Operation         | Description                                  |
|--------------------------|----------------------------------------------|
| Connect-ExchangeOnline   | Establish EXO session using app-only auth    |
| Get-Mailbox              | Retrieve shared mailboxes for selection      |
| Set-Mailbox              | Update shared mailbox                        |
| Disconnect-ExchangeOnline| Close EXO session                            |

### API documentation

- Exchange Online PowerShell overview: https://learn.microsoft.com/powershell/exchange/exchange-online-powershell
- Connect-ExchangeOnline: https://learn.microsoft.com/powershell/module/exchange/connect-exchangeonline
- Get-Mailbox: https://learn.microsoft.com/powershell/module/exchange/get-mailbox
- Set-Mailbox: https://learn.microsoft.com/powershell/module/exchange/set-mailbox
- Disconnect-ExchangeOnline: https://learn.microsoft.com/powershell/module/exchange/disconnect-exchangeonline

## Getting help
> :bulb: **Tip:**  
> For more information on Delegated Forms, please refer to our documentation pages: https://docs.helloid.com/en/service-automation/delegated-forms.html

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/