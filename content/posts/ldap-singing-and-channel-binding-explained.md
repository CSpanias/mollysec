---
title: "LDAP Signing and Channel Binding Explained"
date: "2026-07-01"
author: "mollysec"
description: "How LDAP signing and channel binding work, why they exist, and their role in preventing NTLM relay attacks."
featured: true
tags: ["LDAP","LDAP Signing","LDAP Channel Binding","NTLM Relay","LLMNR Poisoning","Responder"]
categories: ""
series: ""
draft: false
---

# Introduction

We have covered [LLMNR/NBT-NS Poisoning](https://mollysec.com/posts/llmr-nbt-ns-poisoning-explained/) (how to obtain credentials from an Adversary-in-the-Middle (AitM) position) and how [SMB signing](https://mollysec.com/posts/smb-signing-and-ntlm-relay-explained/) prevents those credentials from being relayed over SMB. We will now explore a similar concept, but this time focusing on the **Lightweight Directory Access Protocol (LDAP)**. 

We will start by explaining **what LDAP is** and then have a look at the **mechanisms that prevent relaying** over it. We will keep our scope intentionally tight and won't cover any unrelated aspects such as [LDAP syntax](https://x7331.gitbook.io/boxes/services/tcp/ldap-389-636#ldap-syntax).

Similarly to the SMB protocol, you will have likely encountered LDAP in any Active Directory (AD)-focused lab. Below are some [VL (now HTB) machines](https://www.hackthebox.com/blog/Where-to-find-Vulnlab-content-on-HTB) where LDAP plays a role in solving them:

{{<figure 
    src="/images/ad-boxes-ldap.png"
    alt="A list with AD-focused labs which involve LDAP."
    width="950"
    caption=""
>}}

# TL;DR on LDAP

## What is LDAP?

[LDAP](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/lightweight-directory-access-protocol-ldap-api) is a protocol used to interact with [directory services](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/what-is-a-directory-service), or, in simpler terms, **the language that systems use to query AD**, similar to how web applications use HTTP to speak to web servers.

{{<figure 
    src="/images/ldap-http.png"
    alt="A diagram illustrating the analogy between the LDAP and the HTTP protocol."
    width="950"
    caption=""
>}}

Within an AD environment, LDAP is mostly used for [authentication](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/binding-to-an-ldap-server) and [querying domain information](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/searching-a-directory) (e.g. users and groups), which means that it is used 24/7. Its interactions often involve authenticated requests between systems and Domain Controllers (DCs).

The LDAP service runs on DCs and (typically) listens on the following TCP ports:
- [389 &rarr; LDAP](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/using-ldap-init#simple-authentication-and-security-layer-protocol) (plaintext communication; no encryption or integrity protection by default)
- [636 &rarr; LDAPS](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/using-ldap-init#transport-layer-security-protocol) (LDAP over TLS; historically referred to as LDAP over SSL)

A DC can also hold the [Global Catalog (GC)](https://learn.microsoft.com/en-us/windows/win32/ad/global-catalog) role, accessible via LDAP on TCP ports 3268 (unencrypted) and 3269 (encrypted). The GC contains a partial replica (commonly queried attributes) of all forest objects, which allows efficient cross-domain lookups:

{{<figure 
    src="/images/nmap-ldap-ports.png"
    alt="A screenshot of nmap scanning the LDAP ports of a DC."
    width="950"
    caption=""
>}}

And that's LDAP in a nutshell!

Before diving into signing, we need to briefly talk about how LDAP authentication works.

## LDAP Authentication

LDAP authenticates credentials against AD using a [bind operation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e7d814a5-4cb5-4b0d-b408-09d79988b550). There are two main bind types:
- [Simple](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6a5891b8-928e-4b75-a4a5-0e3b77eaca52) &rarr; the client provides credentials directly to the LDAP server (anonymous, unauthenticated, or username/password). If this is done over LDAP, the password is sent in cleartext. When TLS is used (LDAPS or [StartTLS](https://datatracker.ietf.org/doc/html/rfc4513#section-3)), it is encrypted in transit.
- [Simple Authentication and Security Layer (SASL)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/989e0748-0953-455d-9d37-d08dfbf3998b) → the client first authenticates with another protocol (Kerberos or NTLM) and then uses that to bind to LDAP. This establishes a security context which includes a session key. As we will soon see, this key plays a crucial role in the signing and sealing process.

For our purposes, that's all we need to know about LDAP authentication. The main thing to keep in mind is that **simple bind is incompatible with LDAP signing**. Signing (and sealing!) requires a session key, which simple bind does not provide. **When signing is required, SASL is the only way**!

# LDAP Signing (and Sealing!)

## Signing vs Sealing

Everyone talks about [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing), but hardly anyone mentions sealing. As a matter of fact, I hadn't heard about it myself prior to writing this article! It turns out that signing and sealing are two different protections applied to the same message, both using the session key established during SASL authentication.

Let's see how these work and why both are needed.

For an LDAP message to be signed, the sender computes a cryptographic checksum (MAC) over the data using the session key and includes it with the message. The receiver then recomputes that checksum using the same key and compares the result. If the values match, the message is accepted; otherwise, it is rejected.

This effectively guarantees that the message has not been modified in transit (**integrity**) and that the sender possesses the session key (**implicit authentication**). So far, so good. However, even though both the message and the sender are valid, the message's contents are still transmitted in plaintext. This is where sealing comes into play.

With sealing, the payload itself is encrypted using the same session key. As a result, any intercepted traffic becomes unreadable without access to that key. It provides protection against eavesdropping (**confidentiality**), as well as the same **implicit authentication**, since only parties with the session key can decrypt the data.

{{<figure 
    src="/images/ldap-signing.png"
    alt=""
    width="950"
    caption=""
>}}

In practice, we are only hearing about LDAP signing because modern implementations typically negotiate both signing and sealing when using SASL authentication. Let's recap before we move on, to make sure everything is clear:

|Feature|Traffic|
|--|--|
|**No signing**|Both readable and modifiable|
|**Signing only**|Readable, not modifiable|
|**Signing & sealing**|Neither readable nor modifiable|

## Signing in Practice

On the below (albeit huge) screenshot, we can see **unsigned LDAP traffic**. All communication (authentication, queries, and responses) is transmitted in plaintext, thus, it's susceptible to eavesdropping and tampering via AitM attacks:

{{<figure 
    src="/images/ldap-unsigned-traffic-wireshark.png"
    alt=""
    width="950"
    caption=""
>}}

If we now **enforce signing** and repeat the exchange, first of all, simple bind gets rejected right away:

{{<figure 
    src="/images/ldap-singing-simple-bind-wireshark.png"
    alt=""
    width="950"
    caption=""
>}}

When we switch to SASL authentication (in this case, Kerberos), the bind succeeds. After this point, all communication is protected, meaning that both signing (`krb5_sgn_alg`) and sealing (`krb5_seal_alg`) are applied to each message. Therefore, it is not possible to inspect or tamper with the traffic via an AitM attack:

{{<figure 
    src="/images/ldap-signed-traffic-wireshark.png"
    alt=""
    width="950"
    caption=""
>}}

This difference has a direct impact on **relay attacks**. In the unsigned case, authentication can be relayed successfully:

{{<figure 
    src="/images/ldap-signing-relay-success.png"
    alt=""
    width="950"
    caption=""
>}}

However, once signing is enforced, the same relay attempt is rejected; no session key, no valid signatures, no relay:

{{<figure 
    src="/images/ldap-signing-relay-fail.png"
    alt=""
    width="950"
    caption=""
>}}

# LDAP Channel Binding

[LDAP channel binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing#how-ldap-channel-binding-works) is a mechanism that prevents relay attacks over LDAPS. Let's go over two examples to better understand how this works in practice.

Without channel binding, when a client authenticates using SASL over LDAPS, an attacker in an AitM position can intercept the authentication attempt, and relay it to a DC over a different TLS connection. There is nothing for the DC to verify, so it happily accepts the relay:

{{<figure 
    src="/images/no-channel-binding.png"
    alt=""
    width="950"
    caption=""
>}}

We can confirm this by disabling channel binding on `mollysec-dc01`, attempting HTTP authentication via `DEV01` (`http://<attacker-ip>` as `Administrator`), and relaying this authentication attempt to DC:

{{<figure 
    src="/images/relay-attack-no-cb.png"
    alt=""
    width="950"
    caption=""
>}}

When channel binding is enabled, a Channel Binding Token (CBT) (a hash derived from the initial TLS connection details) is included as part of the authentication process. **The CBT ties the authentication to the TLS connection it was initially created for**.

Now, when the attacker attempts to relay the authentication over a different TLS connection, the DC has to verify that the CBTs match. Since the CBT is tied to the original TLS session, the attacker cannot provide a valid CBT for the new TLS connection, resulting in a mismatch:

{{<figure 
    src="/images/channel-binding.png"
    alt=""
    width="950"
    caption=""
>}}

Repeating the same relay attack, but with **channel binding enforced**, results in the DC rejecting the request:

{{<figure 
    src="/images/relay-attack-cb.png"
    alt=""
    width="800"
    caption=""
>}}

# Configuration and Default Behaviour 

Now that we have a basic understanding of LDAP signing (and sealing!) and channel binding, let's see how they are configured on Windows systems.

For DCs, these GPO settings can be found in the `Default Domain Controllers Policy` under `Domain controller: LDAP server signing requirements` and `Domain Controller: LDAP server channel binding token requirements`:

{{<figure 
    src="/images/gpo-settings-signing-cb-dc.png"
    alt=""
    width="750"
    caption=""
>}}

For clients, the corresponding GPO is called `Network security: LDAP client signing requirements` (channel binding is configured only on the server side) and includes the additional option of `Negotiate signing`:

{{<figure 
    src="/images/gpo-ldap-signing-clients.png"
    alt=""
    width="950"
    caption=""
>}}

Determining the default behaviour for these settings was not a straightforward task (as I naively thought it would be). Microsoft documentation appeared somewhat inconsistent and, on top of that, in some cases, it did not align with how the actual lab was behaving.

For example, some [docs](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing#default-security-behavior) draw the line between Windows Server 2019 and Windows Server 2025, completely ignoring Windows Server 2022 (which happened to be my lab's DC!). In addition, for channel binding the GUI indicates that when its policy is not configured, it defaults to `When Supported`. However, the registry key does not exist, which effectively results in channel binding being set to `Never`:

{{<figure 
    src="/images/cb-reg-key-vs-gpo.png"
    alt=""
    width="950"
    caption=""
>}}

Hopefully, the resulting table is accurate in referencing the default behaviour for both signing and channel binding:

||&le; Win Server 2022|&ge; Win Server 2025|&le; Win 11 (23H2)|&ge; Win 11 (24H2)|
|---|---|---|---|---|
|[**LDAP Signing**](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing#default-security-behavior)|None|Required signing|Negotiate signing|Negotiate signing|
|[**LDAP Channel Binding**](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/domain-controller-ldap-server-channel-binding-token-requirements#default-values)|Never|When supported|Never|When supported|

As you may already have noticed, **modern systems are deployed in a more hardened state by default**. As an example, the corresponding registry keys shown below ([`LDAPServerIntegrity`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server#how-to-set-the-client-ldap-signing-requirement-by-using-registry-keys), [`LDAPClientIntegrity`](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-3-%E2%80%93-enforcing-ldap-signing/4066233#:~:text=LdapClientIntegrity), [`LdapEnforceChannelBinding`](https://support.microsoft.com/en-gb/topic/kb4034879-use-the-ldapenforcechannelbinding-registry-entry-to-make-ldap-authentication-over-ssl-tls-more-secure-e9ecfa27-5e57-8519-6ba3-d2c06b21812e)) demonstrate the default configuration for a Windows Server 2025:

{{<figure 
    src="/images/signing-binding-defaults.png"
    alt=""
    width="950"
    caption=""
>}}

# Mitigation

LDAP signing and channel binding address different aspects of the same problem: the former secures LDAP, while the latter secures LDAPS. Therefore, in order to have complete peace of mind, both need to be enabled.

However, these protections **may impact legacy systems and applications**:
- LDAP signing requires support for SASL-based authentication
- Channel binding depends on the client's ability to include the appropriate binding data during authentication

As a result, these settings are sometimes only partially enforced in production environments. Thorough testing should therefore be performed before enabling them to minimise potential disruptions.

It is also worth noting that **relay attacks depend on both the source and the target protocols**. Even if LDAP or LDAPS is not properly secured, relay attempts may still fail if the originating protocol enforces protections (e.g. SMB signing). Conversely, protocols that do not provide such protections can be reliably used to relay authentication (e.g. [EPA](https://support.microsoft.com/en-au/topic/kb5021989-extended-protection-for-authentication-1b6ea84d-377b-4677-a0b8-af74efbb243f) applied to HTTP).