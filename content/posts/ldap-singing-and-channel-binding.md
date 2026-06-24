---
title: "LDAP Signing and Channel Binding"
date: "2026-06-24"
author: "mollysec"
description: "How LDAP signing and channel binding work, why they exist, and their role in preventing NTLM relay attacks."
featured: true
tags: ["LDAP","LDAP Signing","LDAP Channel Binding","NTLM Relay","LLMNR Poisoning","Responder"]
categories: ""
series: ""
draft: true
---

# Introduction

We have covered [LLMNR/NBT-NS Poisoning](https://mollysec.com/posts/llmr-nbt-ns-poisoning-explained/) (how to get credentials from an Adversary-in-the-Middle (AitM) position) and how [SMB signing](https://mollysec.com/posts/smb-signing-and-ntlm-relay-explained/) prevents from relaying those credentials over SMB. Now, we will go through a similar concept for the Lightweight Directory Access Protocol (LDAP).

We will first talk (very briefly) about why and where LDAP exists and then we will go over the mechanims that exist for preventing an NTLM relay attack over LDAP. And that will be all; we won't touch at all LDAP syntax, how to query information, etc. For this, you can read a bit more [here](https://x7331.gitbook.io/boxes/services/tcp/ldap-389-636).

{{<figure 
    src="/images/ldap-http.png"
    alt="A diagram illustrating the analogy between the LDAP and the HTTP protocol."
    width="950"
    caption=""
>}} 

# TL;DR on LDAP

LDAP, the Lightweight Directory Access Protocol, is a mature, flexible, and well supported standards-based mechanism for interacting with directory servers. It’s often used for authentication and storing information about users, groups, and applications, but an LDAP directory server is a fairly general-purpose data store and can be used in a wide variety of applications.

LDAP is a mechanism for accessing various directory services, including the Active Directory (AD) service in Windows. It typically uses the following four TCP ports:
- Port 389 (unencrypted) 
- Port 636 (encrypted). 

An analogy that might make it more clear (or more messy if you are not familiar with web apps!) is that LDAP is the language that systems use to query AD, similar to how web applications use HTTP to speak to web servers.



A Domain Controller (DC) can also be granted the Global Catalog role which is an LDAP-compliant directory consisting of a partial representation of every object from every domain within the forest. This is available by default on ports 3268 (unencrypted) and 3269 (encrypted).

LDAP authenticates credentials against AD using a BIND operation. This operation establishes the authentication state for an LDAP session. There are two main types of LDAP authentication:

Simple → anonymous, unauthenticated, and username/password authentication. In this method, the client directly provides credentials to the LDAP server.

Simple Authentication and Security Layer (SASL) → allows LDAP to use external authentication services, such as Kerberos, rather than sending credentials directly. The client first authenticates with another system and then uses that trusted identity to bind to LDAP.

SASL/GSSAPI → a common SASL mechanism that integrates LDAP with Kerberos. If an attacker compromises a valid Kerberos ticket, they may be able to bind to LDAP without knowing the user’s password!


Copy
## Simple
Here is my username and password. LDAP, please verify them.

## SASL
I will authenticate using another supported mechanism. LDAP, use that method to verify who I am.

## SASL/GSSAPI
I have already authenticated using another trusted system. LDAP, please trust that authentication.

# LDAP Signing
Enforcing [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) ensures that all LDAP traffic is cryptographically signed, preventing tampering and validating the integrity and authenticity of communications between clients and DCs. Without signing, an attacker positioned on the network can intercept LDAP communications between clients and servers, modify the data in transit, and relay authentication requests, including NTLM hashes, to authenticate as legitimate users. This allows attackers to manipulate LDAP queries, forge responses, and gain unauthorised access based on altered or falsified directory data.

LDAP signing protects LDAP communication over unencrypted channels (TCP 389) by providing integrity, while channel binding protects encrypted LDAP (LDAPS) by binding authentication to the TLS session. Without both, different communication paths remain exposed to relay attacks.

# LDAP Channel Binding
The Domain Controllers (DCs) were configured with unsafe default settings that allow Lightweight Directory Access Protocol (LDAP) clients to communicate without enforcing channel binding.

LDAP channel binding ties authentication credentials to the specific secure channel (e.g., TLS session) being used, preventing credential relay attacks. Without LDAP channel binding, an attacker in a Machine-in-the-Middle (MitM) position can intercept authentication requests sent over a secure outer channel (like TLS) and relay them to a DC over a different connection. Because the DC does not verify that the credentials are bound to the original secure channel, the attacker can successfully authenticate and gain unauthorised access.

Enabling LDAP channel binding ensures that authentication tokens cannot be relayed across different connections, effectively blocking this attack vector.

# NTLM Relay


# Mitigation

From a remediation perspective, LDAP signing should be enforced on all DCs, and LDAP channel binding should be set to “Always” to ensure that authentication is protected against relay attacks and that all communications are cryptographically validated. Legacy systems or older applications may not support LDAP signing or channel binding, which is why these settings are sometimes not enforced.

Modify group policy so that LDAP signing is required:

- This setting can be found under: 'Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options'.
- Change 'Domain controller: LDAP server signing requirements' to 'Require signature'.

In addition, configure LDAP Channel Binding to be enforced as 'Always' (DWORD value: 2) where possible. If this is not feasible due to compatibility constraints, set it to 'When Supported' (DWORD value: 1).

**Note**: Ensure testing is performed to confirm no adverse effects are caused by enabling LDAP signing. In addition, before making any changes to the channel binding configuration it is important to check that any legacy systems in use support connections using this feature.

# References

- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing#how-ldap-channel-binding-works
- [https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-5-–-enforcing-ldap-channel-binding/4235497](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-5-–-enforcing-ldap-channel-binding/4235497)
- https://support.microsoft.com/en-us/topic/kb4034879-use-the-ldapenforcechannelbinding-registry-entry-to-make-ldap-authentication-over-ssl-tls-more-secure-e9ecfa27-5e57-8519-6ba3-d2c06b21812e
- https://www.lrqa.com/en/cyber-labs/hash-relaying-the-path-to-domain-admin/