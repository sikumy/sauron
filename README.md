<div align="center">

# Sauron

<p>
<img src="./banner.png" alt="Sauron ASCII" width="50%">
</p>

**Fast context enumeration for newly obtained Active Directory credentials**

*"One eye to bind them all"*

</div>

## Table of Contents

- [Why Sauron?](#why-sauron)
- [Key Capabilities](#key-capabilities)
- [Quick Installation](#quick-installation)
- [Usage](#usage)
  - [Basic Syntax](#basic-syntax)
  - [Command Line Options](#command-line-options)
  - [Examples](#examples)
  - [Sample Output](#sample-output)
- [Typical Post-Spray Workflow](#typical-post-spray-workflow)
- [Understanding Sauron's Output](#understanding-saurons-output)
- [Contributing](#contributing)
- [Ethical Notice](#ethical-notice)
- [License](#license)

## Why Sauron?

When you obtain fresh credentials (password spraying, phishing, hash replay, etc.), the first thing you need is context: Who is this account really? What groups (direct and nested) does it belong to? Which OUs does it live in? What descriptions reveal its function or linked applications? Sauron answers that in seconds with a single execution.

Primary objective: quickly convert an isolated credential into a mental map of potential capabilities within AD and third-party software/services that reuse corporate groups or descriptions.

## Key Capabilities

- Auto-detection of object type (user, computer, MSA/gMSA, FSP) by sAMAccountName, Distinguished Name, or SID
- Nested group resolution using LDAP rule `1.2.840.113556.1.4.1941` + primary group resolution by SID
- Organizational hierarchy extraction from object to domain root (OUs/containers)
- Metadata extraction: descriptions, notes, titles, departments, managers, adminCount, etc.
- GPO enumeration for linked OUs with enforcement status interpretation
- Connection fallback: LDAPS → insecure LDAPS → LDAP with strongAuthRequired detection
- Debug mode with LDAP request counting and detailed logging
- Structured output of object details, group memberships, organizational units, and policy inheritance

## Quick Installation

Requirements: Python ≥ 3.8

```bash
git clone https://github.com/sikumy/sauron.git
cd sauron
pip install -r requirements.txt
python sauron.py --help
```

## Usage

### Basic Syntax

```bash
python sauron.py -d <DOMAIN> -u <USER> -p <PASSWORD> -dc <DC> -x <IDENTIFIER>
```

Accepted identifiers: sAMAccountName, full DN or SID.

### Command Line Options

| Option | Description |
|--------|-------------|
| `-d / --domain` | AD domain (middleearth.local) |
| `-u / --user` | Username |
| `-p / --password` | Password |
| `-dc` | Domain controller / IP |
| `-x` | Target identifier (auto-detected: sAMAccountName, DN, or SID) |
| `--ssl` | Force LDAPS with automatic fallback |
| `--no-color` | Disable colored output |
| `-v` | Verbose mode (show banner) |
| `--debug` | Detailed logging + request counting |

### Examples

User:
```bash
python sauron.py -d middleearth.local -u strider -p 'Anduril123!' -dc minas-tirith.middleearth.local -x gandalf.wizard --ssl
```

Computer:
```bash
python sauron.py -d middleearth.local -u strider -p 'Anduril123!' -dc minas-tirith.middleearth.local -x PALANTIR01$ --ssl
```

Distinguished Name (DN):
```bash
python sauron.py -d middleearth.local -u strider -p 'Anduril123!' -dc minas-tirith.middleearth.local -x "CN=Aragorn,OU=Rangers,OU=Gondor,DC=middle,DC=earth" --ssl
```

SID / Foreign Security Principal:
```bash
python sauron.py -d middleearth.local -u strider -p 'Anduril123!' -dc minas-tirith.middleearth.local -x "S-1-5-21-111111111-222222222-333333333-4444" --ssl
```

### Sample Output
```
INFO: LDAP - Login successful
Object:
  sAMAccountName: gandalf.wizard
  DisplayName: Gandalf the Grey
  DN: CN=Gandalf,OU=Istari,OU=Wizards,DC=middle,DC=earth
  Description: Senior Wizard - Access to Palantír network and Moria archives
  Notes (info): Master of Elrond's counsel and Ring-bearer guidance
  Title: Wizard of the Grey Order
  Department: Council of the Wise
  Email: gandalf.wizard@middle.earth
  UPN: gandalf.wizard@middle.earth
  userAccountControl: 512 (NORMAL)
  Last Logon: 2024-08-25 14:32:15 UTC
  Password Last Set: 2024-07-15 09:45:22 UTC
  Manager: CN=Manwë,OU=Valar,OU=Ainur,DC=middle,DC=earth  (Manwë the Elder King)
  adminCount: 1
  primaryGroupID: 513
  objectSid: S-1-5-21-1234567890-987654321-1122334455-1001

Groups (including nested and primary group if applicable):
  - Domain Users
      Description: All realm inhabitants
      DN: CN=Domain Users,CN=Users,DC=middle,DC=earth
  - White Council
      Description: High council of the wise and powerful
      DN: CN=White Council,CN=Users,DC=middle,DC=earth
  - Palantír-Administrators
      Description: Access to Palantír seeing-stone network via SAML federation
      managedBy: CN=Elrond,OU=Lords,OU=Rivendell,DC=middle,DC=earth
      DN: CN=Palantír-Administrators,OU=Groups,OU=Wizards,DC=middle,DC=earth
  - Moria-Archive-Access
      Description: Read access to Moria historical archives and genealogies
      Notes (info): Grants research rights to all ancient records and dwarven texts
      DN: CN=Moria-Archive-Access,OU=ServiceGroups,OU=Archives,DC=middle,DC=earth
  - Ring-Bearer-Support
      Description: Administrative support for Ring-bearer missions
      DN: CN=Ring-Bearer-Support,OU=ServiceGroups,OU=Fellowship,DC=middle,DC=earth

OUs/Containers (for the object and its groups, including ancestors):
  - Istari (OU)
      DN: OU=Istari,OU=Wizards,DC=middle,DC=earth
      Description: Order of Wizards sent by the Valar
      Managed By: CN=Manwë,OU=Valar,OU=Ainur,DC=middle,DC=earth
      GPO Links:
        * Default Realm Policy
            Description: Standard security settings for Middle-earth
            SYSVOL Path: \\middle.earth\sysvol\middle.earth\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}
            versionNumber: 182
            Created: 2024-01-15 10:30:45 UTC
            Last Modified: 2024-08-20 16:22:33 UTC
            DN: CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=middle,DC=earth
            gPLink flags: 0 (Link enabled, not enforced)
        * Wizard Security Policy
            Description: Enhanced magical security settings for wizard order
            SYSVOL Path: \\middle.earth\sysvol\middle.earth\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}
            versionNumber: 45
            Created: 2024-03-10 08:15:12 UTC
            Last Modified: 2024-08-18 11:45:07 UTC
            DN: CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=middle,DC=earth
            gPLink flags: 2 (Link enabled and enforced (no block inheritance))
  - Users (Container)
      DN: CN=Users,DC=middle,DC=earth
      Description: Default container for user accounts

INFO: LDAP Statistics: 8 total requests made
```

## Typical Post-Spray Workflow
1. Obtain valid credentials (maybe using [SpearSpray](https://github.com/sikumy/spearspray) 😉)
2. Run Sauron against the obtained accounts (do any belong to sensitive groups?)
3. Extract implicit roles from descriptions and group names
4. Decide next steps: escalate, lateral movement, pivot to applications, report finding

## Understanding Sauron's Output

### Object Attributes
| Attribute | Meaning | Security Context |
|-----------|---------|------------------|
| `sAMAccountName` | Account login name | Primary identifier for authentication |
| `DisplayName` | Human-readable full name | Often reveals role/function when different from username |
| `DN` | Distinguished Name | Shows exact AD location and organizational structure |
| `Description` | Free-text description | **Critical**: Often contains access details, application references, or functional roles |
| `Notes (info)` | Additional free-text info | **Key**: May contain specific permissions, access scopes, or operational details |
| `Title` | Job title | Indicates organizational privilege level |
| `Department` | Business unit | Shows scope of potential access/systems |
| `Email` | Email address | Contact information and potential external access vector |
| `UPN` | User Principal Name | Alternative login format (user@domain) |
| `userAccountControl` | Account status flags | **Critical**: Shows account state (disabled, locked, password policies, delegation trust) |
| `Last Logon` | Most recent authentication | Indicates account activity level (stale accounts = potential targets) |
| `Password Last Set` | Password change timestamp | Shows password age |
| `Manager` | Direct supervisor DN | Potential social engineering target or escalation path |
| `adminCount` | Protected object flag | `1` = high-privilege account (Domain Admins, etc.) |
| `primaryGroupID` | Default group RID | Usually Domain Users (513), Computers (515), or Controllers (516) |
| `objectSid` | Security Identifier | Unique ID for access control decisions |

### Group Information
| Field | Meaning | Security Context |
|-------|---------|------------------|
| `Description` | Group purpose | **Key**: May reveal third-party app access (AWS, Jenkins, VMware, etc.) |
| `Notes (info)` | Additional details | Often contains specific permissions or access scopes |
| `managedBy` | Group manager DN | Administrative contact, **not** necessarily with edit permissions |
| `DN` | Group location | Shows organizational scope (domain-wide vs. OU-specific) |

### OU/Container Information
| Field | Meaning | Security Context |
|-------|---------|------------------|
| `Name (Type)` | OU/Container display | Human-readable name with organizational type (OU/Container) |
| `DN` | Full distinguished name | Complete path in AD hierarchy |
| `Description` | OU purpose | May indicate environment (prod/dev) or function |
| `Managed By` | OU manager DN | Administrative contact for organizational unit |
| `gPOptions` | GP inheritance settings | Controls how policies flow down the hierarchy |
| `GPO Links` | Applied policies | Shows inherited security settings and restrictions |

### GPO Details
| Field | Meaning | Security Context |
|-------|---------|------------------|
| `displayName` | Policy friendly name | Often indicates purpose (security, software deployment, etc.) |
| `Description` | Policy details | May reveal applied restrictions or software |
| `SYSVOL Path` | File system location | Shows policy storage and versioning |
| `versionNumber` | Policy version | Higher numbers indicate recent changes |
| `Created` | Policy creation date | Shows when policy was first implemented |
| `Last Modified` | Policy change date | **Important**: Recent changes may indicate active management |
| `DN` | Policy distinguished name | Location in AD policies container |
| `gPLink flags` | Link enforcement | See GPO link options below |

#### GPO Link Options (Flags)
| Flag | Status | Enforcement | Description |
|------|--------|-------------|-------------|
| `0` | Enabled | Not enforced | Standard policy application, can be blocked by inheritance |
| `1` | Disabled | Not enforced | Policy is disabled and won't apply |
| `2` | Enabled | Enforced | Policy is enforced, cannot be blocked by inheritance |
| `3` | Disabled | Enforced | Policy is disabled but marked as enforced |

> **Pro Tip**: Pay special attention to `Description` fields and group names containing technology names (AWS, Jenkins, VMware, SQL, etc.) - these often indicate access to critical infrastructure or third-party applications that use AD for authentication.

## Contributing
Contributions are welcome! Feel free to open issues for bug reports, feature requests, or submit pull requests to improve the tool.

## Ethical Notice  
Use Sauron only in environments where you have explicit authorization. Misuse may be illegal.

## License
This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.

## Author

**sikumy**

---

*Sauron - Fast Active Directory context enumeration for newly obtained credentials.*