# PowerShell Admin Tools

A small set of PowerShell tools for handling various admin tasks. More tools may be added in the future

## Current Tools

### Backup-CA.ps1
Provides capabilities for backing up and restoring a windows certificate authority.
#### Features:
- CA Backup
- CA Restore
- Password file creation (containing a securestring)
- Backup / Restore of CAPolicy.inf
- Backup / Restore of CertEnroll
- Backup / Restore of CA Registry entries
- Old backup cleanup
- Backup of published Templates
- Works with Task Scheduler

---

### Sign-Script.ps1
Provides capabilities for signing scripts.
#### Features:
- Sign script via thumbprint
- Sign script via serial number
- Cert selection from store (Cert:\CurrentUser\My) for signing

---

### Delete-Certificate.ps1
Provides capabilities for completely deleting certificates (including private keys, which remain stored on the computer when just deleting the certificate in certlm.msc or certmgr.msc).
#### Features:
- Certificate deletion
- WhatIf for showing paths to certificates and keyfiles
- List certificates in store
- Autocompletion for stores

## Help
All commands have a build in -Help parameter. When using it syntax information, examples and a parameter list is provided.
