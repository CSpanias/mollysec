---
title: "Password Audits Part 2: Hash Organisation"
date: 2026-03-14
author: "mollysec"
description: "Article focusing the process of organizing the hashes extracted from the NTDS.dit file (Active Directory's database), during the password audit process."
featured: true
tags: [
]
categories: [

]
series: "Password Audits"
thumbnail: "/images/password-audits-part-2-thumbnail.jpg"
draft: true
---

# Introduction

With NTDS.dit and the SYSTEM hive successfully extracted, we're ready to proceed to the password cracking phase. The next section of this guide will cover hash extraction from the NTDS database, optimal Hashcat configuration for password auditing, and analysis techniques for identifying systemic password weaknesses in the organization.

# Organising secrets

- How the current tool (`secretsorganise`) works exactly?
- Are there other open-source tools that are better?
- If not, can we make it better?
- We crack the `[ALL]-[NTLM].txt` file that outputs

# Output Handling and Organization

Regardless of extraction method, we need to organize output files for efficient downstream processing. A standardized directory structure prevents confusion during multi-DC extractions and long-duration engagements.

We recommend organizing files hierarchically with separate directories for extraction, cracking, and analysis phases:

```
password_audit/
├── extraction/
│   ├── dc01_ntds_20240315/
│   │   ├── ntds.dit
│   │   ├── SYSTEM
│   │   └── extraction_metadata.txt
│   ├── dc02_ntds_20240315/
│   └── combined_hashes.txt
├── cracking/
│   ├── hashcat_sessions/
│   └── cracked_passwords.txt
└── analysis/
    └── password_audit_report.xlsx
```

File naming conventions should include the DC hostname to track the source when extracting from multiple DCs, a date and timestamp for tracking multiple extractions during long engagements, and optionally the extraction method for troubleshooting if we're comparing different approaches.

# Preparing Hashes for Cracking

> Compare how each tool output the hashes!

Most extraction methods output hashes in formats compatible with Hashcat or John the Ripper. Secretsdump's `.ntds` file uses this format:

```
DOMAIN\\username:RID:LM_hash:NTLM_hash:::
```

For Hashcat, we typically extract just the NTLM hashes:

```bash
cat extracted_creds.ntds | cut -d: -f4 > ntlm_hashes.txt
```

Or preserve username associations for analysis:

```bash
cat extracted_creds.ntds | cut -d: -f1,4 --output-delimiter=: > user_ntlm_pairs.txt
```

The username-hash pairing is particularly valuable during the analysis phase when we need to identify which accounts use weak passwords and correlate cracking success with privilege levels or organizational roles.

# Cracking NTLMs

> Should be here or a part by itself?

- using multiple runs of hashcat
- rockyou → rockyou + rules → weakpass_4a → weakpass_4a + rules
- Is this the best way for our restricted time?
- Can we do a better job since we can leave it running in out-of-work hours for at least 3-4 days?
- We don’t utilise sessions, could that help?
- Is it this how actual attackers would try to crack?

**Next:** [Password Audits Part 3: Hash Analysis →](/posts/password-audits-part-3/)