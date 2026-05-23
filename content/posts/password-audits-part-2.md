---
title: "Password Audits Part 2: Hash Organisation"
date: 2026-05-17
author: "mollysec"
description: "Fine-tuning secretsdump output."
featured: true
tags: []
categories: []
series: "Password Audits"
draft: false
---

# Introduction

In [Part 1](/posts/password-audits-part-1/), we talked about how we can extract credentials from `NTDS` using [DCSync](/posts/password-audits-part-1/#dcsync-via-drsuapi) and [VSS](/posts/password-audits-part-1/#vss). Now, it is time to think how to best handle the `NTDS` file. Extracting `NTDS` is typically the last step in a CTF, but it is just the first one here:

---
~~Extract NTDS~~ &rarr; **Clean/Organise NTDS** &rarr; Crack hashes &rarr; Generate stats.  

---

The good news is that this part is technically much simpler; no need to talk about weird acronyms, protocols, and methods. We just need to decide what we actually need from `NTDS` and extract it. 

This article will be mostly myself thinking out loud as of why we need or don't need certain elements. While reading this, make sure to keep in mind my [fair warning](../about/#why-mollysec); it is there for a reason!

At the end of this, I will try to "create" (i.e., vibe-code) a minimal bash-based script to automate the whole process. It will be so simple, that even I will be wondering why did I even vibe-code it. But its 2026, so why not?

{{<figure 
    src="/images/vibe-coding-check.png"
    alt="A man lying on his sofa enjoying a drink while saying to a robot 'Build an app. I will vibe-check it later'."
    width="500"
    caption=""
>}}

Let's get started!

# TL;DR on NTLM

Before deciding what we need, let's first establish what the extracted `NTDS` contains. In our case, it will only contain [New Technology LAN (Local Area Network) Manager (NTLM)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview) hashes that look like this:

> `PUPPY.HTB\levi.james:1103:aad3b435b51404eeaad3b435b51404ee:ff4269fdf7e4a3093995466570f435b8:::`

Let's break down each part so we know with what we are dealing with:

- `PUPPY.HTB` → domain
- `levi.james` → username
- `1103` → [Relative Identifier (RID)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#rid-allocation)
- `aad3b435b51404eeaad3b435b51404ee` → [LM hash](https://learn.microsoft.com/en-us/archive/blogs/miriamxyra/stop-using-lan-manager-and-ntlmv1)
- `ff4269fdf7e4a3093995466570f435b8` → NT hash

Our (main) goal here is to recover the last part of the NTLM (the NT) hash. The LM part will, more often than not, have the value of `aad3b435b51404eeaad3b435b51404ee` which is a placeholder value indicating that this method is disabled.

Nevertheless, besides the fact that LM is considered the "[*grandpa of authentication*](https://learn.microsoft.com/en-us/archive/blogs/miriamxyra/stop-using-lan-manager-and-ntlmv1#first-step-audit)" (implemented in 1987!), we will have to check if it is present within NTDS as there are still environments out there that actually use it!

{{<figure 
    src="/images/win-nt-3.1.png"
    alt="The logo and user interface of Windows NT 3.1."
    width="700"
    caption=""
>}}

# Filtering NTDS

At this point, we want to only keep data that represents actual risk within the domain. Therefore, we will try removing anything that be considered as noise.

As a Proof of Concept (PoC), I will use an expanded version of the NTDS from Hack The Box's [Puppy](https://www.hackthebox.com/machines/puppy) machine. The original one did not contain any LM hashes and I also needed to add some testing-related accounts (you will understand why a bit later) so I had to add those.

So let's start with the NTDS extraction command. Our goal is to assess the domain, therefore, we only need:
- NTLM hashes → `-just-dc-ntlm`
- Enabled accounts (represent actual risk in case of a compromise) → `-user-status`

```bash
# Extract only the NTLM hashes from NTDS and include user status (enabled/disabled)
$ secretsdump.py puppy.htb/steph.cooper_adm:'Pass123'@10.129.232.75 -user-status -just-dc-ntlm -outputfile puppy.htb
```

The above command will create a single file (`puppy.htb.ntds`) with a list of NTLM hashes and their statuses:

```bash
# Check the format
$ head -n5 puppy.htb.ntds
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb0edc15e49ceb4120c7bd7e6e65d75b::: (status=Enabled)
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (status=Disabled)
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a4f2989236a639ef3f766e5fe1aad94a::: (status=Disabled)
PUPPY.HTB\levi.james:1103:aad3b435b51404eeaad3b435b51404ee:ff4269fdf7e4a3093995466570f435b8::: (status=Enabled)
PUPPY.HTB\ant.edwards:1104:aad3b435b51404eeaad3b435b51404ee:afac881b79a524c8e99d2b34f438058b::: (status=Enabled)
```

As we said, we only need enabled accounts, so let's filter out the disabled ones:

```bash
# Extract only enabled objects
$ grep '(status=Enabled)' puppy.htb.ntds.expanded | awk '{print $1}' > ntds-enabled

# Check output
$ head -n3 ntds-enabled
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb0edc15e49ceb4120c7bd7e6e65d75b:::
PUPPY.HTB\levi.james:1103:aad3b435b51404eeaad3b435b51404ee:ff4269fdf7e4a3093995466570f435b8:::
PUPPY.HTB\ant.edwards:1104:aad3b435b51404eeaad3b435b51404ee:afac881b79a524c8e99d2b34f438058b:::
```

Besides disabled accounts, machine accounts (e.g. `DC01$`) can be excluded as well. These typically have Windows-generated (long and automatically rotated) passwords, which are practically non-crackable. Let's seperate them from the user accounts:

```bash
# Extract machine accounts
$ awk -F ':' '$1 ~ /\$$/' ntds-enabled > ntds-machines

# Check output
$ head -n5 ntds-machines
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:::
SQL01$:1000:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:::

# Extract user accounts
$ awk -F ':' '$1 !~ /\$$/' ntds-enabled > ntds-user-accounts

# Check output
$ head -n3 ntds-user-accounts
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb0edc15e49ceb4120c7bd7e6e65d75b:::
PUPPY.HTB\levi.james:1103:aad3b435b51404eeaad3b435b51404ee:ff4269fdf7e4a3093995466570f435b8:::
PUPPY.HTB\ant.edwards:1104:aad3b435b51404eeaad3b435b51404ee:afac881b79a524c8e99d2b34f438058b:::
```

Next, we need to get rid of the testing accounts. The client usually provides us with two accounts: a normal user account and a Domain Admin account. These have different naming conventions for each company, but almost always include a testing-related string, for example, 'test' or the company's name. Let's say our company is called MollySec and that the provided accounts are `mollysec_user` and `mollysec-admin`.

It makes sense to remove them as these are temporary accounts (or at least they should be!) created by the client just for us and not actual domain users. Imagine delivering a report to the client claiming that we recovered X% of their DA accounts while including our own testing account in. That sounds wrong, doesn't it?

```bash
# Extract the testing accounts
$ grep -i 'mollysec' ntds-user-accounts > ntds-testing-accounts

# Check output
$ cat ntds-testing-accounts
PUPPY.HTB\mollysec_user:1108:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
PUPPY.HTB\mollysec-admin:1108:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::

# Filter out the testing accounts
$ grep -vi 'mollysec' ntds-user-accounts > ntds-user-accounts-clean
```

We now have our "main" file (`ntds-user-accounts-clean`) that includes **enabled**, **non-testing**, **user accounts**. At this stage, we can split the NTLM hashes into two parts: NT and LM. Keep in mind that the presence of LM hashes is a finding by itself!

```bash
# Extract NTML hashes
$ cut -d ':' -f4 ntds-user-accounts-clean | sort -u > ntds-ntlm-hashes

# Check output
$ head -n3 ntds-ntlm-hashes
32ed87bdb5fdc5e9cba88547376818d4
3c59dc048e8850243be8079a5c74d079
5fbc3d5fec8206a30f4b6c473d68ae76

# Extract full records with LM hashes
$ grep -v 'aad3b435b51404eeaad3b435b51404ee' ntds-user-accounts-clean > ntds-lm-hashes-full

# Check output
$ head -n3 ntds-lm-hashes-full
PUPPY.HTB\legacy.user1:1401:e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c:::
PUPPY.HTB\legacy.user2:1402:bcb2335c8c5a3ae691aab0a6e6c3d5c5:32ed87bdb5fdc5e9cba88547376818d4:::
PUPPY.HTB\svc_legacy:1403:4a3b108f3fa6cb6d22aad3b435b51404:5fbc3d5fec8206a30f4b6c473d68ae76:::

# Extract LM hashes
$ cut -d ':' -f3 ntds-lm-hashes-full | sort -u > ntds-lm-hashes

# Check output
$ cat ntds-lm-hashes
32ed87bdb5fdc5e9cba88547376818d4
5fbc3d5fec8206a30f4b6c473d68ae76
8846f7eaee8fb117ad06bdd830b7586c
```

As we stand, we have the following files:

```bash
$ ls -lh ntds-*
-rw-r--r-- 1 mollysec mollysec 2.1K May 19 19:37 ntds-enabled
-rw-r--r-- 1 mollysec mollysec   99 May 19 19:39 ntds-lm-hashes
-rw-r--r-- 1 mollysec mollysec  289 May 19 19:38 ntds-lm-hashes-full
-rw-r--r-- 1 mollysec mollysec  159 May 19 19:35 ntds-machines
-rw-r--r-- 1 mollysec mollysec  330 May 19 19:38 ntds-ntlm-hashes
-rw-r--r-- 1 mollysec mollysec  197 May 19 19:38 ntds-testing-accounts
-rw-r--r-- 1 mollysec mollysec 1.9K May 19 19:37 ntds-user-accounts
-rw-r--r-- 1 mollysec mollysec 1.7K May 19 19:38 ntds-user-accounts-clean
```

The important thing for now, is that we have two ready-to-be-cracked files: `ntds-ntlm-hashes` and `ntds-lm-hashes`. You might be wondering how the cracked hashes will be "glued" back to their users, but we will talk about that in Part 4.

At this point, I think we can all agree that none of the individual steps was particularly complex in the above process. However, repeating the process manually would be tedious and could introduce errors. So let's automate it.

The goal is not to create the next 10k star GitHub repo, but simply convert the above process into a minimal bash-based tool for our own ease of use.

# Vibe-Coding

Well, I hope you did not expect me to explain how I vide-coded [`hash-organiser`](https://github.com/CSpanias/hash-organiser)! I just passed the above process to Copilot and asked him to generate a minimal bash script. Nothing fancy here!

You might see that the final script includes some optional stuff that we haven't talked about, but you can just ignore those for now:

```bash
$ ./hash-organiser.sh
Hash Organiser v1.0

Usage:
  ./hash-organiser.sh -n <ntds_file> [options]

Options:
  -n, --ntds     NTDS dump file (required)
  -u, --users    BloodHound users JSON (optional)
  -o, --output   Output directory (default: hash-organiser)
  -f, --filter   Filter pattern (e.g. 'test|company')
  -p, --potfile  Hashcat potfile (optional)
  -h, --help     Show this help
```

Let's test it out:

```bash
$ ./hash-organiser.sh --ntds puppy.htb.ntds.expanded
[*] Hash Organiser v1.0 starting...
[+] Output directory: hash-organiser

[*] Processing NTDS...
[+] Users retained: 20
[+] NTLM hashes extracted
    → hash-organiser/ntlm-hashes.txt
[!] LM hashes detected
    → hash-organiser/lm-hashes.txt

[✔] Completed
[+] Output: hash-organiser
```

All required files seem to have been generated:

```bash
$ tree hash-organiser/
hash-organiser/
├── lm-hashes.txt
├── lm-users.txt
├── ntds-disabled.txt
├── ntds-enabled.txt
├── ntds-machines.txt
├── ntds-users-clean.txt
└── ntlm-hashes.txt

1 directory, 7 files
```

```bash
$ for file in $(ls hash-organiser); do echo -e "Reading file: $file\n"; head -n3 hash-organiser/$file; echo -e "\n"; done
Reading file: lm-hashes.txt

4a3b108f3fa6cb6d22aad3b435b51404
bcb2335c8c5a3ae691aab0a6e6c3d5c5
e52cac67419a9a224a3b108f3fa6cb6d


Reading file: lm-users.txt

PUPPY.HTB\legacy.user1:1401:e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c:::
PUPPY.HTB\legacy.user2:1402:bcb2335c8c5a3ae691aab0a6e6c3d5c5:32ed87bdb5fdc5e9cba88547376818d4:::
PUPPY.HTB\svc_legacy:1403:4a3b108f3fa6cb6d22aad3b435b51404:5fbc3d5fec8206a30f4b6c473d68ae76:::


Reading file: ntds-disabled.txt

Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a4f2989236a639ef3f766e5fe1aad94a:::
PUPPY.HTB\adam.silver:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::


Reading file: ntds-enabled.txt

Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb0edc15e49ceb4120c7bd7e6e65d75b:::
PUPPY.HTB\levi.james:1103:aad3b435b51404eeaad3b435b51404ee:ff4269fdf7e4a3093995466570f435b8:::
PUPPY.HTB\ant.edwards:1104:aad3b435b51404eeaad3b435b51404ee:afac881b79a524c8e99d2b34f438058b:::


Reading file: ntds-machines.txt

DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:::
SQL01$:1000:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:::


Reading file: ntds-users-clean.txt

Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb0edc15e49ceb4120c7bd7e6e65d75b:::
PUPPY.HTB\levi.james:1103:aad3b435b51404eeaad3b435b51404ee:ff4269fdf7e4a3093995466570f435b8:::
PUPPY.HTB\ant.edwards:1104:aad3b435b51404eeaad3b435b51404ee:afac881b79a524c8e99d2b34f438058b:::


Reading file: ntlm-hashes.txt

32ed87bdb5fdc5e9cba88547376818d4
3c59dc048e8850243be8079a5c74d079
5fbc3d5fec8206a30f4b6c473d68ae76
```

# Conclusion

We now have our NTDS file processed and two clean datasets ready for cracking: NT hashes and LM hashes.

In the next part, we will focus on recovering plaintext passwords using [Hashcat](https://github.com/hashcat/hashcat); first manually to understand the process, and then by automating it with vibe-coding, just like we did here.

**Next:** [Password Audits Part 3: Hash Analysis →]
<!-- (/posts/password-audits-part-3/) -->