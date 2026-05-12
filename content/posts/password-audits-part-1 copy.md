---
title: "NTDS Extraction Methods"
date: "2026-03-13"
author: "mollysec"
description: "Article focusing the process of NTDS.dit file, Active Directory's database, during the password audit process."
featured: true
tags: [

]
categories: [

]
series: "Password Audits"
thumbnail: "/images/password-audits-part-1-thumbnail.jpg"
draft: true
---

# Introduction



# Pre-requisites

Plaintext passwords are typically stored in the server's database as [hashes](https://en.wikipedia.org/wiki/Cryptographic_hash_function). In an Active Directory (AD) environment, the server is the [Key Distribution Centre (KDC)](https://learn.microsoft.com/en-us/windows/win32/secauthn/key-distribution-center), the database is the [NT Directory Services Directory Information Tree](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/mcm-core-active-directory-internals/1785782) (NTDS.dit or just NTDS), and the hash format is [New Technology Lan Manager (NTLM)](https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm#ntlm-noninteractive-authentication).

A password converted into an NTLM hash looks like this:

```bash
$ echo -n 'Passw0rd123!' | iconv -t utf16le | openssl md4 -provider legacy
MD4(stdin)= ab4f5a5c42df5a0ee337d12ce77332f5
```

When a user logs into a domain-joined machine, the process looks as follows:

{{<figure 
    src="/images/hash-process.png"
    alt="A user types his password, the password transforms into a hash, which is then compared with the one stored in the database."
    width="900"
    caption=""
>}} 

If the password hash matches the one stored in the database, authentication succeeds.

An important thing to note is that this article is based around the context of an internal pentest. Therefore, we don't have to "*hack*" our way to DA, but we are handed a DA account by the client.

# DRSUAPI (DCSync)

This is the default method of most tools and for good reason: it is fast as it avoids disk I/O entirely; all data is transmitted over the network via RPC (TCP 135) and dynamic high ports (TCP 49152-65535). If your are using this and it's failing for no apparent reason, check if those RCP ports are blocked!

Within an AD domain, there are multiple Domain Controllers (DCs), and, for the authentication process to work harmoniously, every DC must have a copy of the same NTDS. This is achieved by the [Replication](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts?source=recommendations) process; a process responsible for keeping every DC in sync with each other. This process happens on regular intervals via the [Directory Replication Service Remote Protocol (MS-DRSR)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47); the protocol which DCs use to communicate and sync their databases with each other.

The goal here is to make our host look like a DC and then ask a legit DC to sync with it; hence the name: **DC-Sync**. We should note that not everyone can ask for a DC to sync with them; that would be [glaikit](https://www.visitscotland.com/things-to-do/attractions/arts-culture/scottish-languages/scots-words-meanings#glaikit). As we will soon see, two permissions are required for that and a DA account has both by default. 

{{<figure 
    src="/images/look-at-me-i-am-the-dc-now.png"
    alt="A meme saying: 'Look at me, I am the DC now'."
    width="500"
    caption=""
>}}

DRS has two RPC interfaces, but our focus here is on the [DRSUAPI](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/58f33216-d9f1-43bf-a183-87e3c899c410) and its [`IDL_DRS`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/58f33216-d9f1-43bf-a183-87e3c899c410) methods. When we run Impacket's `secretsdump.py` (or NetExec's `--ntds`), we are triggering a sequence of DRS calls:

## DRS Calls

### 1. IDL_DRSBind - The Handshake

Before we can request anything, we first need to establish a connection with the DC by calling the [`IDL_DRSBind`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/605b1ea1-9cdc-428f-ab7a-70120e020a3d) method. This creates a `DRS_HANDLE` (kind of a session token) that proves we've successfully authenticated and are authorised to make replication requests. This handle remains valid for all subsequent operations until we explicitly call `IDL_DRSUnbind` or the server invalidates it (e.g., due to timeout or errors).

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

When a tool fails with a `bind failed` error, something has gone wrong in this step.

### 2. IDL_DRSGetNCChanges - Replication

This is the step that replicates directory data from the DC to our host. To call the [`IDL_DRSGetNCChanges`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b63730ac-614c-431c-9501-28d6aca91894) function we need the [Replicating Directory Changes](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes) permission. However, just calling `IDL_DRSGetNCChanges` only returns non-secret directory data (e.g. usernames, group memberships, OUs, etc.) and deliberately excludes credentials.

To get the actual credentials, we need to include the [`EXOP_REPL_SECRETS`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/565aadc5-c890-47fd-bbf5-7da4b0018813) flag; in order to do that, we need the [Replicating Directory Changes All](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all) permission.

The [Replicating Directory Changes In Filtered Set](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-in-filtered-set) permission might also be needed when dealing with [RODC](https://learn.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema), but that had never happened to me during my extensive three months-career on internal tests.

<!-- {{<figure 
        src="/images/makes-sense-fallon.gif"
        alt="A meme showing Jimmy Fallon undestanding something."
        width="300"
        caption=""
>}} -->

After the session is established, Secretsdump calls `DRSGetNCChanges` (including the `EXOP_REPL_OBJ` flag) for each user. An interesting thing to note is that the `uuidDsaObjDest`and `uuidInvocIdSrc` variables are the GUIDs that identify the destination and source DCs in a replication operation. Since we're not a real DC, secretsdump sets both to the target DC's GUID to make the request appear legitimate:

{{<figure 
    src="/images/impacket-drsuapi-2.png"
    alt="The relevant code snippet from secretsdump."
    width="800"
    caption=""
>}}

### 3. IDL_DRSUnbind - Cleanup

Once the replication is completed, [`IDL_DRSUnbind`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/49eb17c9-b6a9-4cea-bef8-66abda8a7850) is called to explicitly close the connection and release the `DRS_HANDLE`. Interestingly, secretsdump doesn't explicitly call `DRSUnbind` in the code. The DRS handle is implicitly released when the script exits or the DC times out the session.

## FAQ

- *Didn't we say that DCSync mimics DC-to-DC replication? But our attacking machine isn't a DC, right?*

Legitimate DCs only talk through Kerberos with [mutual authentication](https://learn.microsoft.com/en-us/windows/win32/ad/about-mutual-authentication-using-kerberos) (so both sides verify who they're talking to) and [encrypted traffic](https://learn.microsoft.com/en-us/windows/win32/ad/integrity-and-privacy) (so the exchanged data stays safe in transit). We want to leveraege the legit DC-to-DC sync process, but we don't want the security protections that come with it.

- *If the DCSync process only uses Kerberos, how can we use NTLM hashes (e.g. `secretsdump.py -hashes`)?*

When a **non-DC host** connects to a DC, the DC don't give a [puck](https://www.dota2.com/hero/puck) about mutual authentication and encryption; it accepts both Kerberos and NTLM authentication. The DC will only check if our account has the replication permissions.

- *What are the differences between the legit Replication process and DCSync?*

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

# VSS