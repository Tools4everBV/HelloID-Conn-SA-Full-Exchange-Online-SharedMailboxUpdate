# HelloID-Conn-SA-Full-Exchange-Online-SharedMailboxUpdate

| :information_source: Information |
| :------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible for acquiring the connection details such as organization name, application ID, certificate, etc. You might need to coordinate with the client's application manager before implementing this connector. |

## Description

HelloID-Conn-SA-Full-Exchange-Online-SharedMailboxUpdate is a delegated form designed for use with HelloID Service Automation (SA). It can be imported into HelloID and customized according to your requirements.

By using this delegated form, you can update an existing shared mailbox in Exchange Online. The following options are available:

1. Search and select a shared mailbox (wildcard search by name and email addresses)
3. Edit the display name, alias, and/or email address
   > Display name is validated for uniqueness in Microsoft Entra ID
   > Email address is validated for uniqueness in Microsoft Entra ID
   > Alias is validated for uniqueness in Microsoft Entra ID
4. Configure the email address handling:
   > **Set as Primary Email**: The email address becomes the new primary SMTP address, and the current primary email is converted to an alias in proxy addresses
   > **Add as Alias**: The email address is added as a secondary SMTP address (alias) in proxy addresses
5. Update the shared mailbox
   > The shared mailbox is updated using the provided display name, alias, and email address. The mailbox proxy addresses are rebuilt to reflect the changes while preserving existing proxy addresses.

## Getting started

### Requirements

#### App Registration & Certificate Setup

Before implementing this connector, make sure to configure a Microsoft Entra ID App Registration. During the setup process, you'll create a new App Registration in the Entra portal, assign the necessary API permissions, and generate and assign a certificate.

Follow the official Microsoft documentation for creating an App Registration and setting up certificate-based authentication:

- [App-only authentication with certificate (Exchange Online)](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#set-up-app-only-authentication)

#### HelloID-specific configuration

Once you have completed the Microsoft setup and followed their best practices, configure the following HelloID-specific requirements.

- **API Permissions** (Application permissions):
  - `User.Read.All` - To validate email and alias uniqueness by listing users via Graph API
  - `Domain.Read.All` - To retrieve verified domains for the mail domain dropdown
  - `Exchange.ManageAsApp` - To update and manage shared mailboxes
- **Entra ID Role assignment:**
  - Assign the **Exchange Administrator** role to the App Registration
- **Certificate:**
  - Upload the public key file (.cer) in Entra ID
  - Provide the certificate as a Base64 string in HelloID. For instructions on creating the certificate and obtaining the base64 string, refer to our forum post: [Setting up a certificate for Microsoft Graph API in HelloID connectors](https://forum.helloid.com/forum/helloid-provisioning/5338-instruction-setting-up-a-certificate-for-microsoft-graph-api-in-helloid-connectors#post5338)

### Connection settings

The following global variables must be configured in HelloID when importing and configuring the delegated form.

| Setting | Description | Mandatory |
| --- | --- | --- |
| EntraIdOrganization | The Entra organization name (domain) | Yes |
| EntraIdTenantId | The Entra tenant ID (GUID) | Yes |
| EntraIdAppId | The unique identifier (ID) of the App Registration in Microsoft Entra ID | Yes |
| EntraIdCertificateBase64String | The Base64-encoded string representation of the app certificate | Yes |
| EntraIdCertificatePassword | The password associated with the app certificate | Yes |

## Remarks

### Display Name, Email Address & Alias Validation via Graph API

- **Performance optimization**: Instead of using the Exchange Online cmdlet `Get-Mailbox` (which can take 30+ seconds per query), the connector uses the Microsoft Graph API to validate display name, email address, and alias uniqueness
- **Validation scope**: Checks for uniqueness across all types of objects in Entra ID (users, shared mailboxes, room mailboxes, equipment mailboxes, etc.)
- **Graph API filters**: Uses OData `$filter` queries on the following properties:
  - `displayName` - Display name
  - `mailNickname` - Mail nickname/alias
  - `mail` - Primary SMTP address
  - `proxyAddresses` - Proxy addresses (both smtp and SMTP variants)
- **Three separate data sources**:
  - `EntraID-Check-DisplayName-Unique` - Validates the display name uniqueness
  - `EntraID-Check-EmailAddress-Unique` - Validates the email address uniqueness
  - `EntraID-Check-Alias-Unique` - Validates the alias uniqueness

### Mailbox Search and Update

#### Shared Mailbox Search Process

The form includes a search field that retrieves matching shared mailboxes using Exchange Online cmdlets:

1. **Search Mailboxes** (`Get-Mailbox` cmdlet)
   - **Mailbox type**: Filters by `RecipientTypeDetails = SharedMailbox`
   - **Search criteria**: Matches against `Alias`, `Name`, and `PrimarySmtpAddress`
   - **Wildcard support**: Uses wildcard matching to find partial matches
   - Returns a list of shared mailboxes for selection

#### Shared Mailbox Update Process

When the form is submitted, the following process occurs in Exchange Online:

1. **Update Mailbox Properties** (`Set-Mailbox` cmdlet)
   - **Display Name**: Updated to the value entered in the form
   - **Mailbox Name**: Updated to the value entered in the form
   - **Alias**: Updated to the specified alias value
   - **Email Address Handling**: Based on the "Set as Primary Email" option:
     - **If enabled**: Email address is set as the new primary SMTP address (uppercase "SMTP:" prefix)
     - **If disabled**: Email address is added as a secondary SMTP address/alias (lowercase "smtp:" prefix)

2. **Proxy Address Management**
   - The script rebuilds the proxy addresses based on the selected option
   - **When setting as primary email**:
     - The new email address is added with uppercase "SMTP:" prefix (primary)
     - All existing primary addresses are converted to secondary (lowercase "smtp:")
     - Existing proxy addresses are preserved to maintain email routing
   - **When adding as alias**:
     - The new email address is added with lowercase "smtp:" prefix (alias)
     - The current primary SMTP address remains unchanged
     - Existing proxy addresses are preserved
   - Duplicate addresses are automatically removed before adding the new address

## Development resources

### API endpoints

The following Microsoft Graph API endpoints are used by the connector:

| Endpoint | Description |
| --- | --- |
| `/v1.0/domains` | Retrieve all verified domains with Email support for the mail domain dropdown |
| `/v1.0/users` | Search and retrieve users to validate email address and alias uniqueness |

### PowerShell Cmdlets

The following PowerShell cmdlets are used by the connector:

| Cmdlet | Description |
| --- | --- |
| `Connect-ExchangeOnline` | Establish session to Exchange Online using certificate-based app-only authentication |
| `Get-Mailbox` | Search and retrieve shared mailboxes for selection |
| `Set-Mailbox` | Update mailbox properties including display name, alias, and primary SMTP address |
| `Disconnect-ExchangeOnline` | Close the Exchange Online session |

### Documentation

For more information on the APIs and PowerShell cmdlets used in this connector, please refer to:

**Microsoft Graph API:**
- [Authentication with certificate](https://learn.microsoft.com/graph/auth-v2-service)
- [List domains](https://learn.microsoft.com/graph/api/domain-list)
- [List users - Advanced query capabilities](https://learn.microsoft.com/graph/aad-advanced-queries)
- [User resource reference](https://learn.microsoft.com/graph/api/user-list)

**Exchange Online PowerShell:**
- [Exchange Online PowerShell overview](https://learn.microsoft.com/powershell/exchange/exchange-online-powershell)
- [Connect-ExchangeOnline](https://learn.microsoft.com/powershell/module/exchange/connect-exchangeonline)
- [Get-Mailbox](https://learn.microsoft.com/powershell/module/exchange/get-mailbox)
- [Set-Mailbox](https://learn.microsoft.com/powershell/module/exchange/set-mailbox)
- [Disconnect-ExchangeOnline](https://learn.microsoft.com/powershell/module/exchange/disconnect-exchangeonline)

## Getting help

> 💡 **Tip:**  
> For more information on Delegated Forms, please refer to our [documentation](https://docs.helloid.com/en/service-automation/delegated-forms.html) pages.

## HelloID docs

The official HelloID documentation can be found at: [https://docs.helloid.com/](https://docs.helloid.com/)
