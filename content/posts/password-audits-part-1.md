---
title: "Password Audits Part 1: NTDS Extraction"
date: "2026-03-13"
author: "mollysec"
description: "NTDS extraction methods."
featured: true
tags: [

]
categories: [

]
series: "Password Audits"
thumbnail: "/images/password-audits-part-1-thumbnail.jpg"
draft: true
---

# What about Password "Audits"?

>**Note**: This article focuses on the, one-level deep, technical mechanics of NTDS extraction during pentests. OPSEC considerations are out of scope. Sorry!

I recently went from testing (close-to-zero-functionality) APIs to testing, almost, everything. I am talking about web apps, GraphQL APIs, cloud configs, build reviews, external and internal assessments, the whole shebang.

<!-- It sounds like a lot, isn't? I might need to ask for a raise...

{{<figure 
    src="/images/broke-make-it-rain.gif"
    alt="A meme showing a man that make a dollar note to dissappear."
    width="330"
    caption=""
>}}  -->

One part of internal testing is conducting a **Password Audit**, which can be summed up as follows:

---
Extract NTDS &rarr; Clean/Organise NTDS &rarr; Recover NTDS &rarr; Generate stats.  

---

Sounds simple, doesn't it? Well, for normal people, it is actually pretty straightforward and even boring after a while! But I am not one of those people. One of my greatest joys in life is to overcomplicate the simple things.

So, buckle up.

# TL;DR on NTDS

As you probably know already, passwords are stored server side in databases in a strange-looking format called a hash. In an AD environment, this database is called [NT Directory Services Directory Information Tree](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/mcm-core-active-directory-internals/1785782) (NTDS.dit) and is located within the Key Distribution Centre (KDC).

{{<figure 
    src="/images/hash-process.png"
    alt="A user types his password, the password transforms into a hash, which is then compared with the one stored in the database."
    width="900"
    caption=""
>}} 

Some relevant facts about NTDS:
* Every domain controller (DC) contains a copy of the NTDS.
* All DCs are kept in sync with each other via a process called [Replication](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts?source=recommendations).
* NTDS is encrypted, therefore, unusable by itself (shoot!).
* The SYSTEM registry hive has the encryption key, aka SYSKEY (phew!).

The bottom line is that we need both the NTDS and the SYSKEY in order to decrypt the former and get the hashes. Remember that we are talking about testing and not *hacking*, so we get handed both on a silver plate. The *testee* gives us a Domain Admin (DA) account which has permissions (more on that later) to obtain both with a single command. Life is good!

Imagine now that someone thought to write a whole article for that single command...

{{<figure 
    src="/images/spongebob-delulu.gif"
    alt="A meme of spongebob saying 'Delulu'."
    width="400"
    caption=""
>}} 

# NTDS Extraction

Since we don't need to *hack* our way into DA, our goal is to get the NTDS **as complete and as fast as possible**. We can do that both remotely (DRSUAPI or VSS) or locally (NTDSUTIL or VSSADMIN). 

If those acronyms don't ring a bell, worry not; it is almost certain that you have used them multiple times already!

In practice, NTDS extraction comes down to two approaches: DSRUAPI (DCSync) and VSS.

# DRSUAPI

## Theory

This is the **DCSync** approach, the default method of most tools. It's the fastest one as it avoids disk I/O entirely; all data is transmitted over the network via RPC (TCP 135) and dynamic high ports (TCP 49152-65535). If you are using this and it's failing for no apparent reason, check if those RPC ports are blocked!

The goal of DC-Sync is in the name: **impersonate a DC and ask a legit DC to sync with us**.

{{<figure 
    src="/images/look-at-me-i-am-the-dc-now.png"
    alt="A meme saying: 'Look at me, I am the DC now'."
    width="500"
    caption=""
>}}

This process is known as **DC-to-DC replication** and is a legit process that happens on regular intervals via the [Directory Replication Service Remote Protocol (MS-DRSR)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47). Simply put, the DRS protocol is what DCs use to communicate and sync their databases with each other.

The DRS protocol has two RPC interfaces, but we mostly care about the one: **DRSUAPI**. This is because DRSUAPI includes the [`IDL_DRSGetNCChanges`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b63730ac-614c-431c-9501-28d6aca91894) function which is a part of the [`IDL_DRS`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/58f33216-d9f1-43bf-a183-87e3c899c410) methods. We will dig more into that later.

Obviously, not everyone can ask a DC for data, that would be [glaikit](https://www.visitscotland.com/things-to-do/attractions/arts-culture/scottish-languages/scots-words-meanings#glaikit). But DAs have the permissions to do it, more specifically, the [Replicating Directory Changes](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes) and [Replicating Directory Changes All](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all). We will see why we need both of them soon.

>[Replicating Directory Changes In Filtered Set](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-in-filtered-set) might also be needed when dealing with [RODC](https://learn.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema), but that had never happened to me during my extensive three months-career doing internal testing.

When we run Impacket's `secretsdump.py` (or NetExec's `--ntds`), we are triggering a sequence of DRS calls:

1. **IDL_DRSBind** (The Handshake)

    Before we can request anything, we first need to establish a connection with the DC. This method creates a `DRS_HANDLE` (kind of a session token) that proves we've successfully authenticated and are authorised to make replication requests. This handle remains valid for all subsequent operations until we explicitly call `IDL_DRSUnbind` or the server invalidates it (e.g., due to timeout or errors).

    When a tool fails with a `bind failed` error, something has gone wrong here.

2. **IDL_DRSGetNCChanges** (Replicating Data)

    This is the function that actually replicates directory data from the DC to our host. To call this function we need the **Replicating Directory Changes** permission. However, just calling `IDL_DRSGetNCChanges` only returns non-secret directory data (e.g. usernames, group memberships, OUs, etc.) and deliberately excludes credentials.

    To get the actual credentials, we need to include the [`EXOP_REPL_SECRETS`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/565aadc5-c890-47fd-bbf5-7da4b0018813) flag. In order to do that, we need the **Replicating Directory Changes All** permission.

    Now you know why we need both permissions!

    {{<figure 
        src="/images/makes-sense-fallon.gif"
        alt="A meme showing Jimmy Fallon undestanding something."
        width="300"
        caption=""
    >}}

3. **IDL_DRSUnbind** (Cleanup)

    Once we've replicated what we need, my assumption was that well-behaved tools would call `IDL_DRSUnbind` to explicitly close the connection and release the `DRS_HANDLE`; however, that was not the case.

Some questions might have surfaced through your mind by now:
- *Didn't we say that DCSync mimics DC-to-DC replication? But our attacking machine isn't a DC, right?*

    Here's the thing: legitimate DCs only talk through Kerberos with [mutual authentication](https://learn.microsoft.com/en-us/windows/win32/ad/about-mutual-authentication-using-kerberos) (so both sides verify who they're 
    talking to) and [encrypted traffic](https://learn.microsoft.com/en-us/windows/win32/ad/integrity-and-privacy) (so the exchanged data stays safe in transit). We want to use the legitimate DC-to-DC sync process, but we don't want the security protections that come with it.

- *But if the DCSync process only uses Kerberos, how can we use NTLM hashes (e.g. `secretsdump.py -hashes`)?*

    Well, here's the interesting part: when a **non-DC host** connects to a DC, the DC couldn't give a [puck](https://www.dota2.com/hero/puck) about mutual authentication and encryption; it accepts both Kerberos and NTLM authentication. The DC will only check if our account has the replication permissions.

|Legit DC Replication|DCSync|
|---|---|
|Requests all changes since last sync (incremental)|Requests specific objects with secrets (targeted)|
|Updates replication metadata to track sync state|Doesn't update any replication metadata|
|Happens continuously in the background between DCs|One-time operation initiated by us|
|Requests everything (objects, attributes, metadata, etc.)|Only requests credential-related attributes|

Another thing to point out is that when our tool of choice connects to a DC for replication, it constructs a very [specific SPN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/41efc56e-0007-4e88-bafe-d7af61efd91f):

```text
General format:
E3514235-4B06-11D1-AB04-00C04FC2DCD2/<target DC GUID>/<domain FQDN>
         └─ Fixed DRS interface GUID (same for every DC)

Example:
E3514235-4B06-11D1-AB04-00C04FC2DCD2/f8a7c3d2-4b9e-4a1f-9d6c-2e5f8b3a7c14/mollysec.local
```

When we see Kerberos errors, like `KDC_ERR_S_PRINCIPAL_UNKNOWN`, it often means something is wrong with this SPN. As I'm sure, we've all experienced, this is why specifying a DC by its IP address can cause authentication problems; the SPN expects a proper FQDN. Falling back to NTLM authentication (using `-hashes`) often works around the problem.

{{<figure 
    src="/images/fqdn-kerberos.png"
    alt="A meme highlighting the common issue of neglecting to use Fully Qualified Domain Names (FQDNs) when using Kerberos."
    width="500"
    caption=""
>}}

Enough theory for now; let's see `secretsdump.py`'s DCSync implementation.

## Secretsdump

> Why don't we extract the LA's from the DCs???

Impacket's [secretsdump.py](https://github.com/fortra/impacket/blob/master/impacket/examples/secretsdump.py) performs a DCSync operation by default:

```bash
secretsdump.py MOLLYSEC.LOCAL/molly:Pass123@192.168.1.5
```

Let's see how secretsdump implements the three-step DRSUAPI process that we are now experts on:

{{<figure 
    src="/images/youre-dealing-with-an-expert-professional.gif"
    alt="A meme of a soldier ironically saying 'You are dealing witht an expert'."
    width="500"
    caption=""
>}}

1. **IDL_DRSBind** (The Handshake)
    
    Secretsdump establishes a DRS session with the DC via the `DRSBind` method by negotiating capabilities:

    {{<figure 
        src="/images/impacket-drsuapi-1.png"
        alt="The relevant code snippet from secretsdump."
        width="800"
        caption=""
    >}}

    The key flags here are:
    - `NTDSAPI_CLIENT_GUID`: Identifies our host as a replication client to the DC.
    - `DRS_EXT_GETCHGREQ_V6/V8`: Protocol version negotiation, supports both older (2003) and newer (2008+) DCs.
    - `DRS_EXT_STRONG_ENCRYPTION`: Ensures AES-encrypted communication.

2. **IDL_DRSGetNCChanges** (Replicating Data)

    After the session is established, Secretsdump calls `DRSGetNCChanges` (including the `EXOP_REPL_OBJ` flag) for each user:

    {{<figure 
        src="/images/impacket-drsuapi-2.png"
        alt="The relevant code snippet from secretsdump."
        width="800"
        caption=""
    >}}

    An interesting thing to note is that the `uuidDsaObjDest` and `uuidInvocIdSrc` variables are the GUIDs that identify the destination and source DC in the replication operation. Since we're not a real DC, secretsdump sets both to the target DC's GUID to make the request appear legitimate.

3. **IDL_DRSUnbind** (Cleanup)

    Interestingly, secretsdump doesn't explicitly call `DRSUnbind` in the code. The DRS handle is implicitly released when the script exits or the DC times out the session.

Once secretsdump receives the encrypted attributes from the DC, it:
1. Decrypts them using the session key from `DRSBind`.
2. Formats the output (e.g., `username:rid:lmhash:nthash:::`).
3. Writes to stdout or the specified output files.

# VSS

## Theory

The [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service) (VSS) method is a fundamentally different approach from DRSUAPI. The goal here is to:
1. Access the DC locally
2. Create a snapshot (a point-in-time copy) of its disk
3. Copy NTDS and SYSTEM from that snapshot

The issue here is that AD constantly uses NTDS and, as a result, it is always locked; VSS solves that problem.

{{<figure 
    src="/images/spongebob-squarepants.gif"
    alt="The character Spongebob saying 'Problem solved'."
    width="300"
    caption=""
>}}

Unlike DRSUAPI, which we need replication permissions (DA-level access), VSS requires just Local Administrator (or even Backup Operator) access to the DC. However, since this process involves disk I/O, it is slower than DRSUAPI. In addition, VSS makes a snapshot of the entire volume; it is not a targeted credential-grabbing like DRSUAPI.

So why we would ever want to use the slower VSS method instead of DRSUAPI?, I hear you ask.

The obvious answer is when we are not a DA but just an LA on a DC. Also, another use case could be that the required RPC ports for DRSUAPI are blocked, but SMB access is available.

The VSS process looks like this:

1. Create a shadow copy of the volumne contaings NTDS (e.g. a snapshot of the `C:\` drive).
2. Access the snapshot via its kernel device path (something like `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\`).
3. Copy NTDS (`Windows\NTDS\`) and SYSTEM (`Windows\System32\config\`) from the snapshot  to a target location (e.g. `\Temp`).
4. Delete the snapshot.

Like DRSUAPI, where we *kind of* mimicked the DC-to-DC replication process, here we *kind of* mimicking the VSS process.

Because it is a native Windows process, it does automatically means that it's *stealthy*: the pattern of creating a shadow copy, immediately accessing NTDS, and then deleting the snapshot is a pretty clear indicator of credential dumping.

<!-- {{<figure 
    src="/images/i-think-its-obvious-kyle-broflovski.gif"
    alt="The character Kyle from Southpark saying 'I think it's obvious'."
    width="500"
    caption=""
>}} -->

## Secretsdump

When we use secretsdump with the `-use-vss` flag, the execution path changes from the default DRSUAPI to VSS:

{{<figure 
    src="/images/impacket-use-vss.png"
    alt="Secretsdump help menu explaining the -use-vss flag."
    width="650"
    caption=""
>}}

1. **Remote Service Creation**

    Secretsdump connects to the DC's **Service Control Manager (SCM)** (the Windows component that manages services) via RPC over SMB and starts the `RemoteRegistry` service. This service allows remote access to the registry, which is needed to extract the SYSTEM hive (containing the SYSKEY used to decrypt NTDS later):

    {{<figure 
        src="/images/impacket-vss-1.png"
        alt="The relevant code snippet from secretsdump."
        width="600"
        caption=""
    >}}

2. **Shadow Copy Creation**

    Then, it executes `vssadmin` on the DC to create the volume snapshot. The command is executed remotely using one of several methods (`-exec-method` flag): creating a temporary service via SCM (default), using WMI, or other remote execution techniques:

    {{<figure 
        src="/images/impacket-vss-2.png"
        alt="The relevant code snippet from secretsdump."
        width="850"
        caption=""
    >}}

3. **File Extraction via SMB**

    Once the shadow copy exists, secretsdump accesses it via the `ADMIN$` share and uses SMB to copy both NTDS and SYSTEM from the snapshot to the target machine:

    {{<figure 
        src="/images/impacket-vss-3.png"
        alt="The relevant code snippet from secretsdump."
        width="600"
        caption=""
    >}}

4. **Shadow Copy Deletion**

    After copying the files, secretsdump deletes the shadow copy:

    {{<figure 
        src="/images/impacket-vss-4.png"
        alt="The relevant code snippet from secretsdump."
        width="400"
        caption=""
    >}}

Here's a handy recap:

| Aspect | DRSUAPI | VSS |
|---|---|---|
| **Network protocol** | RPC (DRSUAPI calls) | RPC (SCM) + SMB (file transfer) |
| **Data format** | Encrypted attributes in DRS responses | Raw ESE database file |
| **Decryption** | Session key from DRSBind | SYSKEY from SYSTEM hive |
| **Extraction granularity** | Per-user (can target specific accounts) | All-or-nothing (entire database) |
| **Speed** | Fast (streaming data) | Slow (snapshot + file copy) |
| **Disk footprint on DC** | None | Temporary shadow copy |


## NetExec as a Wrapper

NetExec makes heavy use of Impacket scripts and its [`smb.py`](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/protocols/smb.py) script, which includes the NTDS extraction module, is no different.

The [`--ntds`](https://www.netexec.wiki/smb-protocol/obtaining-credentials/dump-ntds.dit?q=raw-ntds-copy#dump-all-users-from-the-ntds.dit) flag is simply a wrapper around Impacket's `secretsdump`. In brief, it imports `NTDSHashes` from secretsdump and calls it with `useVSSMethod=False`, triggering its DRSUAPI code path. This is identical to running `secretsdump.py -just-dc` directly.

{{<figure 
    src="/images/nxc-drsuapi-1.png"
    alt="The relevant code snippet from netexec's smb.py script."
    width="500"
    caption=""
>}}

{{<figure 
    src="/images/nxc-drsuapi-2.png"
    alt="The relevant code snippet from netexec's smb.py script."
    width="300"
    caption=""
>}}

Just like DRSUAPI, NetExec also includes the [`--ntds vss`](https://www.netexec.wiki/smb-protocol/obtaining-credentials/dump-ntds.dit?q=raw-ntds-copy#dump-all-users-from-the-ntds.dit) flag, which simply sets `useVSSMethod=True` and triggers the VSS path:

{{<figure 
    src="/images/nxc-drsuapi-3.png"
    alt="The relevant code snippet from netexec's smb.py script."
    width="500"
    caption=""
>}}

<!--

### Practical Features (DRSUAPI + VSS)

|Flag|Description|
|---|---|
|`just-dc`|Extracts only NTDS.DIT data (NTLM hashes and Kerberos keys).|
|`-just-dc-ntlm`|Extracts only NTLM hashes. Faster for large domains.|
|`-just-dc-user`|Extracts credentials for a specific user only.|
|`-history`|Includes password history entries using the `ntPwdHistory` and `lmPwdHistory` attributes.|
|`-resumefile`|Tracks progress by recording the last successfully processed user SID. If extraction is interrupted, subsequent runs can resume from the last checkpoint rather than starting over.|
|`-outputfile`|Generates multiple files containing different credential types: `.ntds` (NTLM hashes), `.ntds.cleartext` (cleartext passwords), `.ntds.kerberos` (Kerberos keys), `.sam` (SAM database hashes), `.secrets` (LSA secrets, cached credentials, and machine account passwords).|
|`-pwd-last-set`|Displays when each password was last changed based on the `pwdLastSet` attribute.|
|`-user-status`|Show whether accounts are enabled, disabled, or locked.|

> TO-CHECK: `user-status` is binary (enabled/disabled) or includes locked?


### Practical Features (VSS)

The VSS method supports most of the same flags as DRSUAPI mode, plus one more:

| Flag | VSS Support | Notes |
|---|---|---|
| `-exec-method` | ⚠️ VSS-specific | Choose how to execute remote commands: `smbexec`, `wmiexec`, `mmcexec` (default: `smbexec`) |

**Additional VSS-specific considerations:**

```bash
# Specify custom execution method (useful if SMB is restricted)
secretsdump.py 'DOMAIN/username:password@<DC_IP>' -use-vss -exec-method wmiexec

# VSS extraction with NTLM hash (no Kerberos issues!)
secretsdump.py -hashes :8846f7eaee8fb117ad06bdd830b7586c 'DOMAIN/username@<DC_IP>' -use-vss
```

Secretsdump uses a multi-protocol approach that requires both SMB and RPC access. The tool first establishes an SMB connection (TCP 445) for authentication and initial enumeration, then performs the actual DCSync operation using the DRSUAPI protocol over RPC. This SMB-first behavior has practical implications for network-restricted environments.

When using Kerberos authentication, secretsdump requires the `CIFS/domaincontroller` SPN to establish the initial SMB session:

```python
rpc.set_smb_connection(self.__smbConnection)
```

If we're operating in an environment where SMB is restricted or blocked but LDAP remains available, secretsdump may fail where pure LDAP-based methods succeed. This is the key distinction between secretsdump and Mimikatz's DCSync implementation. Mimikatz uses LDAP for its initial authentication and connection establishment, then proceeds to DRSUAPI for the credential extraction. This LDAP-based approach allows Mimikatz to function in environments where SMB access is restricted, while secretsdump's SMB dependency can become a limiting factor. For most password audit engagements, this distinction is academic since both SMB and LDAP are typically accessible to Domain Admin credentials.

Using `-just-dc-ntlm` restricts extraction to NTLM hashes only, significantly reducing both processing time and network bandwidth. For comprehensive password audits requiring Kerberos keys and cleartext passwords, omitting this flag ensures complete credential material extraction.

## DCSync via Mimikatz

Mimikatz's DCSync module performs the same Directory Replication Service operations as secretsdump, but with a pure LDAP-based approach. Unlike Impacket's SMB-first methodology, Mimikatz doesn't require CIFS SPNs or SMB access, which can be advantageous in certain network configurations.

The command for complete credential extraction is:

```bash
lsadump::dcsync /domain:targetdomain.com /all /csv
```

For targeting specific high-value accounts:

```bash
lsadump::dcsync /domain:targetdomain.com /user:Administrator
```

The LDAP-only operation works well in environments where SMB faces additional restrictions. Mimikatz displays hashes immediately in real-time output without creating intermediate files, which can be useful for quick verification. The selective extraction capability allows us to target specific accounts when we need rapid confirmation of particular credentials before committing to a full NTDS extraction.

However, Mimikatz requires execution on a Windows host, typically accessed via RDP or WinRM. The output requires parsing if we need standardized file formats compatible with our cracking tools, as the default console output isn't optimized for direct ingestion into Hashcat or John the Ripper.


# Common Issues and Troubleshooting

## Incomplete Hash Extraction

Comparing hash counts against expected user counts provides quick validation. We can verify the approximate user count with `net user /domain` and compare against the number of hashes extracted. Significant discrepancies warrant re-running the extraction and comparing outputs for consistency.

-->

**Next:** [Password Audits Part 2: Hash Organization →](/posts/password-audits-part-2/)