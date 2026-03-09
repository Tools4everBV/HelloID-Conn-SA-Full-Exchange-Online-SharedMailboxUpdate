# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [2.1.0] - 2026-03-09

### Added
- Display name validation using Microsoft Graph API for uniqueness checks across all Entra ID objects
- New validation data source `EntraID-Check-DisplayName-Unique` for real-time display name uniqueness validation
- Email address mode selection: option to set as primary SMTP address or add as alias/secondary address
- Flexible proxy address management supporting both primary email replacement and alias addition

### Changed
- Email address handling now supports two modes:
  - **Set as Primary Email**: Converts email to primary SMTP address (uppercase "SMTP:"), demotes existing primary to alias
  - **Add as Alias**: Adds email as secondary SMTP address (lowercase "smtp:"), preserves current primary
- Validation now includes three separate data sources (DisplayName, EmailAddress, and Alias)
- Proxy address management enhanced to handle both primary and alias scenarios
- Duplicate email addresses automatically removed before adding new addresses
- README updated with comprehensive documentation of new email handling modes and display name validation

## [2.0.0] - 2025-02-26

### Added
- Certificate-based authentication support for Microsoft Entra ID and Exchange Online
- Email address and alias validation using Microsoft Graph API for improved validation performance
- Search functionality to find shared mailboxes by alias, name, or email address with wildcard support
- Real-time validation data sources for email and alias uniqueness checks across all Entra ID objects
- Proxy address management to properly rebuild email addresses when updating primary SMTP
- Two separate validation data sources for email and alias uniqueness checks
- Comprehensive README with detailed setup instructions, form workflow, and API documentation

### Changed
- **BREAKING**: Migrated authentication from secret-based to certificate-based authentication
  - Old variables: `EntraSecret`, `EntraTenantId`, `EntraAppID`, `EntraOrganization`
  - New variables: `EntraIdCertificateBase64String`, `EntraIdCertificatePassword`, `EntraIdOrganization`, `EntraIdTenantId`, `EntraIdAppId`
- **Performance**: Changed mailbox validation from `Get-Mailbox` cmdlet (30+ seconds) to Microsoft Graph API for email address and alias uniqueness checks
- Form structure completely redesigned with improved field layout and real-time validation
- Naming convention updated to use hyphens (e.g., "Exchange online - Shared Mailbox - Update")
- Data sources refactored:
  - `EntraID-Check-EmailAddress-Unique` - New Graph API-based email validation
  - `EntraID-Check-Alias-Unique` - New Graph API-based alias validation
  - `EntraID-Get-All-MailDomains` - Graph API-based domain retrieval
  - `EXO-Get-Shared-Mailboxes-Wildcard-Name-EmailAddresses` - Improved search functionality
- Mailbox update logic improved:
  - Display Name and Mailbox Name properly updated in form submission
  - Primary SMTP Address updated by rebuilding proxy addresses collection
  - Alias validation before update
  - Existing proxy addresses preserved during primary SMTP change
- Error handling and logging enhanced with better exception handling and context
- README updated with complete documentation and API references
- Required API permissions updated to use Graph API and Exchange.ManageAsApp
- Role assignment changed from "Exchange Recipient Administrator" to "Exchange Administrator"

### Removed
- Legacy authentication method using client secret
- Old global variable structure

### Fixed
- Improved validation performance by switching from Exchange Online cmdlets to Graph API for uniqueness checks
- Enhanced error messages with better context for troubleshooting
- Proxy address handling now properly maintains all existing addresses when updating primary SMTP

## [1.0.0] - 2024-02-12

### Added
- Initial release of HelloID-Conn-SA-Full-Exchange-Online-SharedMailboxUpdate
- Shared mailbox update functionality in Exchange Online
- Form-based mailbox update workflow
- Mailbox property modification (Name, Alias, Primary SMTP Address)

