# PowerShell Admin Tools

A small set of PowerShell tools for handling various admin tasks. More tools may be added in the future

## Current Tools

### Backup-CA.ps1
Provides capabilities for backing up and restoring a windows certificate authority.
#### Features:
- CA Backup
- CA Restore
- Password file creation (containing a securestring)
- Old backup cleanup
- Works with Task Scheduler

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
