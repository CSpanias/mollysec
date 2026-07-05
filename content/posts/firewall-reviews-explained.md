---
title: "Firewall Reviews Explained"
date: "2026-07-03"
author: "mollysec"
description: "?"
featured: true
tags: ["firewall","security","review","rules"]
categories: ""
series: ""
draft: true
---

# Introduction


{{<figure 
    src="/images/"
    alt=""
    width="950"
    caption=""
>}}

Firewall reviews are a common component of infrastructure security assessments, yet many practitioners are unfamiliar with how they are performed in practice.

This article explains:
- The purpose of a firewall review
- Common review methodology
- Typical findings
- Limitations of automated tools
- How firewall security can be assessed manually

# TL;DR on Firewalls

## What Is a Firewall Review?

Objectives + Scope

We get a firewall configuration dump (or running configuration export) which can be huge (multiple files, 6k+ lines each)

### Common Firewall Vendors

- Palo Alto
- Fortinet
- Cisco ASA / Firepower
- Check Point
- Sophos
- Juniper

## 1. Device & Management Plane

### Device Information

* Platform (Cisco FTD, Palo Alto, FortiGate, etc.)
* Software / firmware version
* Hardware model
* Known vulnerabilities
* Support status

- implement searchsploit (+nvd/cve) scan (--vulnerability-scan / -vs)

### Administrative Access

* Local accounts
* TACACS
* RADIUS
* MFA
* RBAC

### Management Services

* SSH
* HTTPS management
* SNMP
* API access
* Restriction of management interfaces

**Why we care**

Compromising the firewall itself bypasses all network segmentation and policy controls.

## 2. Network Architecture

### Interfaces

* Every connection point is an interface.
* Example:

```text
Internet
    ↓
Firewall
    ↓
Corp
```

### Security Zones

Logical groupings of interfaces:

```text
Internet
Corp
DMZ
Management
VPN
```

### Segmentation

The firewall's primary job:

```text
Control traffic between zones
```

Example:

```text
Internet
    ↓
DMZ
    ↓
Corp
```

**Why we care**

Poor segmentation often allows attackers to move from less trusted networks into more trusted networks.

## 3. Access Control

### Firewall Policies

The business logic.

Example:

```text
Users may browse the web
Mail server may send SMTP
VPN users may access file shares
```

### ACLs / Rulebase

The actual firewall rules.

```text
Who can talk to whom
Using which protocol
Using which port
```

### Objects & Object Groups

Objects are labels:

```text
SL1BTPMADCV01
```

instead of:

```text
172.16.50.11
```

Object groups are collections:

```text
Domain Controllers
```

instead of:

```text
DC1
DC2
DC3
```

**Why we care**

Most review findings originate from misconfigured firewall rules.

## 4. Remote Connectivity

### Remote Access VPN

User-to-network access.

VPN pools:

```text
ANYCONNECT_POOL_SL1
```

operate similarly to DHCP scopes and assign addresses to remote users.

Questions:

* Can VPN users reach sensitive systems?
* Is MFA enforced?
* Is split tunnelling enabled?

### Site-to-Site VPN

Network-to-network connectivity.

Examples:

```text
Azure
Partner Networks
Other Offices
```

Tunnel interfaces connect networks rather than users.

**Why we care**

VPNs frequently create trusted paths into critical environments.

## 5. Network Services

### NAT

Address translation.

Questions:

* What is exposed externally?
* What is internally reachable?
* Are public services correctly mapped?

### Routing

* Static routes
* Dynamic routing (BGP, OSPF, etc.)
* Cloud connectivity

### DNS

* Internal resolvers
* External resolvers
* Name resolution dependencies

**Why we care**

Routing and NAT often reveal hidden trust relationships and externally exposed systems.

## 6. Monitoring & Security Controls

### Logging

* Syslog
* Event logging
* Rule logging

### Monitoring

* SNMP
* SIEM integration
* NOC monitoring

### Threat Detection

* IPS
* IDS
* Threat detection features
* Alerting

**Why we care**

A secure firewall that nobody monitors is still a risk.

# Review Methodology

## 1. Understand the Architecture

Identify:

* Interfaces
* Zones
* VPNs
* Routing

Map traffic flows.

## 2. Review Management Security

Assess:

* Admin authentication
* MFA
* TACACS/RADIUS
* Management exposure

## 3. Review Segmentation

Assess:

* Zone boundaries
* Trust relationships
* Management access

## 4. Review Firewall Rules

Assess:

* Necessity
* Scope
* Logging
* Business justification

## 5. Review VPN Access

Assess:

* User VPN access
* Site-to-site trust
* Split tunnelling
* Authentication

## 6. Review Monitoring

Assess:

* Logging
* SIEM integration
* SNMP
* Alerting

# Common Findings

### Any-Any Rules

One of the most common checks during a firewall review is identifying so-called **"Any-Any"** rules.

The term is frequently used in security reports and review methodologies, yet it is often misunderstood. While many reviewers refer to anything containing `any any` as an Any-Any rule, not all rules are equally risky. Before assessing the security impact of a rule, it is important to understand exactly what is being permitted.

A firewall rule generally consists of:

```text
Source -> Destination -> Protocol / Service -> Action
```

For example:

```text
Corp Users -> Internet -> HTTPS -> Permit
```

In this case, internal users are allowed to browse the web over HTTPS.

The **classic (true) Any-Any rule** looks like this:

```text
permit ip any any
```

Breaking it down:

```text
permit = allow
ip     = all IP traffic
any    = any source
any    = any destination
```

In practice, this means:

```text
Anything -> Can communicate with -> Anything
```

From a security perspective, this is typically the most concerning type of rule because it removes the segmentation normally enforced by the firewall. For example, internet users can talk to Domain Controllers or Guest WiFi users to Production servers. For this reason, true Any-Any rules are almost always investigated during a firewall review and frequently result in findings.

### Protocol Any-Any Rules

Not every `any any` rule grants unrestricted access. During the review of the Cisco FTD configuration, several rules similar to the following were identified:

```text
permit gre any any
permit ipinip any any
permit 41 any any
```

At first glance these appear alarming because they contain `any any`, however the protocol is restricted. For example, the first only allows GRE traffic from any source to any destination, rather than "Allow all traffic". Similarly, `permit ipinip any any` allows only IP-in-IP encapsulated traffic. 

These protocols are commonly used for:

* VPN connectivity
* Tunnel interfaces
* Site-to-site connections
* Cloud networking

In our configuration these entries appeared within the **Default Tunnel Action Rule**, suggesting they are used to support VPN infrastructure rather than general user traffic. For this reason, Protocol Any-Any rules are typically classified as: `Review Required` rather than `Finding Confirmed`; context is essential.

### Service Any-Any Rules

Another variation limits traffic by service rather than protocol.

For example, `permit tcp any any eq 3389`:

```text
permit = allow
tcp    = TCP traffic
any    = any source
any    = any destination
3389   = RDP
```

This effectively means:

```text
Anyone
    ↓
Can access
    ↓
RDP on any destination
```

Visualised:

```text
Any Source
     |
   RDP
     |
     v
Any Destination
```

While not a true Any-Any rule, it may still represent excessive access depending on the environment.

Other examples include `permit tcp any any eq 22` and `permit tcp any any eq 445`. These rules warrant review because they expose specific services rather than unrestricted connectivity.

### Broad Access Rules

A fourth category involves large networks rather than the keyword `any`. Consider `permit ip Corp_Network any`; this is not technically an Any-Any rule, yet the effect may be similar.TThe rule allows:

```text
Entire Corporate Network
    ↓
Anything
```

Such rules often emerge over time as environments grow and exceptions accumulate. Although they may have a legitimate business purpose, they deserve the same scrutiny as traditional Any-Any rules.

### Not Every Any-Any Rule Is a Finding

A common mistake during firewall reviews is treating every occurrence of `any any` as a vulnerability.

In reality, the review process should follow this sequence:

```text
Identify Rule
    ↓
Understand Context
    ↓
Determine Purpose
    ↓
Assess Risk
```

For example:

```text
permit ip any any
```

usually represents a significant reduction in network segmentation and should be carefully justified.

Conversely:

```text
permit gre any any
```

may simply be enabling site-to-site VPN functionality and may be entirely legitimate.

The objective of the reviewer is therefore not to find `any any` strings, but to determine whether a rule grants more access than necessary.

This distinction is an important reminder that automated tools can highlight interesting rules, but human analysis is still required to determine whether those rules represent genuine security findings.


### Excessively Permissive Rules

```text
Entire Network
    ↓
Entire Network
```

***

### Weak Administrative Controls

* Local-only authentication
* No MFA
* Excessive admin accounts

***

### Weak Segmentation

```text
Internet
    ↓
Internal Network
```

***

### Excessive VPN Access

```text
VPN Users
    ↓
Entire Corp Network
```

***

### Missing Logging

Traffic permitted but not logged.

***

### Unused / Stale Rules

Rules no longer required.

***

### Shadowed Rules

Rules that can never be matched because an earlier rule overrides them.

***

# Automation

### Automated Analysis

* Configuration parsing
* Rule extraction
* Zone mapping
* VPN inventory
* NAT inventory
* Management surface identification

### Manual Validation

Still required for:

* Rule intent
* Business justification
* Compensating controls
* Risk determination

# Conclusion

