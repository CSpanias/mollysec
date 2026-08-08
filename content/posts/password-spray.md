---
title: "Password Spraying Explained: Policies, Lockouts, and badPwdCount"
date: "2026-08-08"
author: "mollysec"
description: "How password spraying works: from GPOs and FGPPs to badPwdCount, PDC emulators, and the N-2 rule."
featured: true
tags: ["password-spraying","active-directory","fgpp","pso","badpwdcount","conpass","netexec"]
categories: ""
series: ""
draft: false
---

# Introduction

After writing some articles about (what are considered to be) "boring" topics, such as [SMB](https://mollysec.com/posts/smb-signing-and-ntlm-relay-explained/) / [LDAP](https://mollysec.com/posts/ldap-singing-and-channel-binding-explained/) signing, [email security](https://mollysec.com/posts/email-security-explained/), and [firewalls](https://mollysec.com/posts/firewall-security-explained/), I thought I'd dive into something a bit more exciting.

Password spraying is a topic I had wanted to explore for quite some time. I had also starred tools such as [`conpass`](https://github.com/login-securite/conpass), but never found the opportunity to explore the underlying concepts in more detail. Until now. 

In this article, I won't try to replicate hackndo's [post](https://en.hackndo.com/password-spraying-lockout/), although there will be some duplicated information for context purposes, but rather act as a complement to it. As such, some concepts, like GPO and PSO ordering, won't be explained but links for further reading will be provided instead.

Let's get into it!

# Group Policy Objects (GPOs)

The major concern when conducting a password spraying attack is **account lockouts**. If you lock an account out, they will have to ask their (probably understaffed!) IT department to unlock their account and in this way negatively interfere with the organisation's day-to-day operations. Imagine locking hundreds or thousands accounts out!

To avoid the above scenario, the easiest thing to do is take a look at the `Account Lockout Policy` settings of the `Default Domain Policy` Group Policy Object (GPO). The settings we care about from a password spraying perspective are the following:

- [Lockout duration](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada1/5952c7f3-dd4a-4219-bcb1-dba53eb9266e) &rarr; how long a locked account remains unusable before it is automatically unlocked.
- [Lockout threshold](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada1/8424289e-0a60-433e-abd7-02ff0c1afd1b) &rarr; the number of failed authentication attempts that will trigger an account lockout.
- [Reset account lockout timer (observation window)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada1/ac2852b7-cbca-4495-8e66-74fa34bcff59) &rarr; the amount of time a user must avoid failed authentication attempts before the accumulated bad password count is reset.

{{<figure 
    src="/images/pass-spray-gpo-settings.png"
    alt="Inspecting the password-related settings of the Default Domain Policy."
    width="850"
    caption=""
>}}

All **standard users can read the domain's default password policy**, for example, using `nxc`'s [`--pass-pol`](https://www.netexec.wiki/smb-protocol/enumeration/enumerate-domain-password-policy-1) flag:

{{<figure 
    src="/images/pass-spray-nxc-pass-pol.png"
    alt="Querying the domain password policy via netexec."
    width="950"
    caption=""
>}}

The minimum effort we could do in order to avoid lockouts is to **adjust our password spraying strategy to the domain's password policy**. For instance, based on the above policy we could spray three passwords every 10 minutes for each user. This way, we would leave room for the legit user to be able to make a failed authentication attempt without being locked out.

However, we must keep in mind that additional GPOs can define password and account lockout policies. When multiple GPOs contain such settings, only the effective domain password policy matters. The good news is that **standard users can also enumerate the order in which GPOs are applied and therefore infer the effective password policy**. We won't dive into how this works, but feel free to read about it [here](https://en.hackndo.com/password-spraying-lockout/#gpos-application-order).

Spoiler alert, this can be done via the [`gplink`](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-scope#gplink-attribute) attribute.

# Fine Grained Password Policies (FGPPs)

A [Fine-Grained Password Policy (FGPP)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/fine-grained-password-policies?tabs=adac) is an AD feature implemented through Password Settings Objects (PSOs). A PSO contains the same password and account lockout settings traditionally configured in the `Default Domain Policy`, but can be applied directly to specific users and groups, enabling multiple password policies to coexist within the same domain.

PSOs are stored within the `Password Settings Container` under the `System` container. When a PSO applies to a user, it overrides the password and account lockout settings defined in the `Default Domain Policy`:

{{<figure 
    src="/images/pass-spray-fgpp.png"
    alt="An example of an FGPP."
    width="950"
    caption=""
>}}

If multiple PSOs apply, the [`Precedence`](https://en.hackndo.com/password-spraying-lockout/#psos) attribute is used to determine the effective policy, with lower values taking priority and therefore winning the precedence evaluation. The problem with FGPPs is that **standard domain users cannot enumerate their settings**:

{{<figure 
    src="/images/pass-spray-pass-settings-container-perms.png"
    alt="The permissions of the Everyone group on the Password Settings Container."
    width="650"
    caption=""
>}}

As a result, we cannot reliably determine the lockout thresholds applied to affected accounts. We might retrieve the domain password policy, carefully plan a password spraying campaign around it, and still lock out users governed by a more restrictive FGPP.

For example, if we try to enumerate PSOs as a standard user, we can only determine whether any exist:

{{<figure 
    src="/images/pass-spray-pso-settings-su.png"
    alt="Enumerating PSOs as a standard user."
    width="950"
    caption=""
>}}

In contrast, a Domain Admin can enumerate all of their settings:

{{<figure 
    src="/images/pass-spray-pso-settings.png"
    alt="Enumerating PSOs as a domain admin."
    width="950"
    caption=""
>}}

Don't despair yet though!

Fortunately, there are two **world-readable attributes that indicate whether an FGPP applies to an object**:
- The [`msDS-PSOApplied`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/a182b5e8-8141-43e4-9c17-67fade1984a7) attribute contains all PSOs applicable to the target object.
- The [`msDS-ResultantPSO`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ad735d45-ba6a-42fc-a41c-e91ced8e72d9) attribute contains the effective PSO after precedence evaluation has been performed.

Thus, **if either attribute is present on a user object, we know that the account is governed by an FGPP**. Since standard domain users cannot read the associated settings, the safest approach is to exclude such accounts from the spraying dataset altogether.

For example, `sylune` does not have any of these attributes so we can assume that the default password policy is applied to them. On the other hand, `poppy` has the `msDS-PSOApplied` attribute, indicating that an FGPP applies to the account:

{{<figure 
    src="/images/pass-spray-pso-attr-nxc.png"
    alt="Querying the msDS-AppliedPSO attribute as a standard domain user."
    width="950"
    caption=""
>}}

The `msDS-ResultantPSO` attribute is a [constructed attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a3aff238-5f0e-4eec-8598-0a59c30ecd56), meaning that its value is calculated from other AD attributes rather than stored directly on the object. Constructed attributes are not returned by default during LDAP enumeration and cannot be modified manually:

{{<figure 
    src="/images/pass-spray-msds-resultantpso.png"
    alt="Querying the msDS-ResultantPSO attribute as a standard domain user."
    width="950"
    caption=""
>}}

This behaviour makes sense from a performance perspective.

To determine the value of `msDS-ResultantPSO`, AD must first identify all PSOs that apply to the target object, evaluate their precedence values, and determine which policy ultimately wins. This is considerably more expensive than simply returning the list of applicable PSOs through the `msDS-PSOApplied` attribute.

# The badPwdCount Attribute

Let's now talk about the `badPwdCount` attribute, how it works, and how it relates to the lockout process. For a more detailed description (along with some nice diagrams!) see [here](https://en.hackndo.com/password-spraying-lockout/#authentication-mechanism).

The [`badPwdCount`](https://learn.microsoft.com/en-us/windows/win32/adschema/a-badpwdcount) attribute represents the **number of times the user tried to log on to the account using an incorrect password**. When a user attempts to log into a Windows domain, the following steps take place:

1. The Domain Controller (DC) checks if the account is locked.
2. If it is not, it will then check if the provided password is valid.
3. If it is, the user gets authenticated, and `badPwdCount` resets to `0`.
4. If the password is not valid, the user gets a logon failure message and the `badPwdCount` is incremented by `1`.
5. If the failed password attempts reach the `lockoutThreshold` value, the account will be locked and the `lockoutTime` attribute will be filled in.

The `badPwdCount` attribute, unlike most others, is a **non-replicated** attribute which means that it is maintained separately on each DC in the domain. This means that **different DCs can legitimately hold different `badPwdCount` values for the same user at the same point in time**. However, this does not mean that we can (safely) spray passwords against each DC independently (we will see this in practice soon).

Since some attributes are intentionally non-replicated, AD still requires a way to make consistent security-sensitive decisions in order to avoid conflicts across the domain. To address this, AD uses the [**Flexible Single Master Operation (FSMO)**](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/2aae4593-66fa-4d89-a921-1625b19af5b7) roles, where specific DCs are assigned responsibility for particular operations.

There are five FSMO roles in total, but from a password spraying perspective we are primarily interested in the [**PDC emulator**](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f96ff8ec-c660-4d6c-924f-c0dbbcac1527) role. The DC holding this role serves as a coordination point for authentication-related activities across the domain, including password validation and account lockout processing.

In our test lab, `DC01` holds the PDC Emulator role:

{{<figure 
    src="/images/pass-spray-pdc-emulator-dc01.png"
    alt="Querying the PDC Emulator role."
    width="650"
    caption=""
>}}

When I first read about the PDC role, I thought that querying the DC that holds it is all we need to learn the value of `badPwdCount` for a target object. This turned out not to be the case, as **the PDC does not hold an authoritative copy of `badPwdCount`**.

Let's validate all the above with an example.

The user fails authentication two times against `DC02` (`badPwdCount` = `2`) and one time against `DC03` (`badPwdCount` = `1`). The PDC (`DC01`) is updated as failed authentication attempts occur. In this example, its `badPwdCount` value reflects the combined failed authentication attempts observed across `DC02` and `DC03`, resulting in a value of `3`.

Notice that if the user successfully authenticates against `DC01`, the `badPwdCount` attribute does not reset globally (on all DCs) but just locally (on `DC01`):

> *Do your eyes a favour and **open the following screenshots in a new tab**.*

{{<figure 
    src="/images/pass-spray-non-rep-attr.png"
    alt="Verifying the non-replicated nature of the badPwdCount attribute."
    width="950"
    caption=""
>}}

As a result, if the user performs three more failed attempts against `DC02`, the account will be locked:

{{<figure 
    src="/images/pass-spray-non-rep-attr-1.png"
    alt="Verifying the non-replicated nature of the badPwdCount attribute."
    width="950"
    caption=""
>}}

However, if the user authenticates successfully on a non-PDC DC, for example, `DC02`, this would be forwarded to the PDC (`DC01`), so the `badPwdCount` value would be reset on both `DC01` and `DC02` (but not on `DC03`):

{{<figure 
    src="/images/pass-spray-non-rep-attr-2.png"
    alt="Verifying the non-replicated nature of the badPwdCount attribute."
    width="950"
    caption=""
>}}

This behaviour exists to prevent us from bypassing lockout thresholds by distributing failed authentication attempts across multiple DCs, even though the individual `badPwdCount` values themselves remain non-replicated.

For the Wireshark fans out there, packet captures reveal how non-PDC DCs communicate authentication-related events to the PDC, allowing it to participate in lockout decisions even though `badPwdCount` itself is not replicated:

- When a user performs failed authentication attempts against a non-PDC DC (in this case, `DC02`), each failed attempt results in a corresponding [`NetrLogonSamLogonEx`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/25667880-3d51-499b-b228-19c08eb16b81#:~:text=NetrLogonSamLogonEx) exchange between `DC02` and the PDC (`DC01`).
- If the user authenticates successfully against the PDC (`DC01`), the `badPwdCount` value is reset locally on `DC01`, but no corresponding update is observed on `DC02`. In contrast, when the user authenticates successfully against a non-PDC DC (i.e. `DC02`), a [`NetrLogonSendToSam`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/25667880-3d51-499b-b228-19c08eb16b81#:~:text=NetrLogonSendToSam) exchange is observed between `DC02` and the PDC (`DC01`). Following this exchange, the `badPwdCount` value is reset on both `DC02` and `DC01`, but not on other DCs.

{{<figure 
    src="/images/pass-spray-wireshark.png"
    alt="Inspecting RPC netlogon traffic on Wireshark."
    width="950"
    caption=""
>}}

This behaviour explains why tools such as `conpass` query every DC and use the highest observed `badPwdCount` value instead of just querying the PDC!

# The N-2 Rule

The `n-2` rule is a niche AD behaviour that I had no idea about until recently. I first read about this on Richard Mueller's [blog post](https://rlmueller.net/BadPwdAcctLockout.htm). This is a case where failed authentication attempts do not increase the `badPwdCount` attribute!

In brief, if the password attempted matches either of the two most recently used historical passwords (`n-1` or `n-2`), the authentication attempt fails but `badPwdCount` is not incremented. The rationale behind this behaviour is to **avoid punishing users who accidentally attempt to authenticate using a recently changed password**.

Let's validate this with another example.

We have the user with the following password history:

| Position    | Password     |
|-------------|--------------|
| n (current) | Password123! |
| n-1         | Password0!   |
| n-2         | Password1!   |
| n-3         | Password2!   |

In the example below, the user attempts to authenticate using the `n-2` and `n-1` passwords on the 2<sup>nd</sup> and 4<sup>th</sup> attempts, respectively:

{{<figure 
    src="/images/pass-spray-sylune-n-2-tests-kali.png"
    alt="Attempting multiple logins attempts to test the n-2 theory."
    width="950"
    caption=""
>}}

We can confirm that only the 3<sup>rd</sup> and 5<sup>th</sup> attempts incremented `badPwdCount`, while the 2<sup>nd</sup> and 4<sup>th</sup> attempts did not:

{{<figure 
    src="/images/pass-spray-sylune-n-2-tests-ps.png"
    alt="Attempting multiple logins attempts while inspecting the value of the badPwdCount attribute to test the n-2 theory."
    width="950"
    caption=""
>}}

An interesting question is whether these events could be tracked during a password spraying campaign and subsequently used to infer the current password from a previously known one. I think my next `conpass` PR might have just written itself!

# Conclusion

As we have seen throughout this article, avoiding account lockouts during a password spraying campaign is considerably more complex than it might initially appear. 

Determining whether a single authentication attempt is safe may require knowledge of the effective domain password policy, any FGPPs applied to the target account, the maximum `badPwdCount` value observed across all DCs, and even the possibility of legitimate failed authentication attempts by the user.

This complexity explains why mature spraying tools invest significant effort into policy enumeration, account state tracking, and anti-lockout logic rather than simply attempting passwords against every user. Without such safeguards, account lockouts become a question of when rather than if.

Ultimately, safe password spraying is less about choosing passwords and more about understanding how AD processes authentication failures.