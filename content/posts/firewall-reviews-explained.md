---
title: "Firewall Reviews Explained"
date: "2026-07-03"
author: "mollysec"
description: "How to Review a Firewall Configuration."
featured: true
tags: ["firewall","security","review","rules","cisco","asa","ftd"]
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

Firewall (FW) reviews are a common component of infrastructure security assessments, yet many practitioners are unfamiliar with how they are performed in practice.

This article explains:
- The purpose of a firewall review
- Common review methodology
- Typical findings
- Limitations of automated tools
- How firewall security can be assessed manually

# TL;DR on Firewalls

What is a firewall?
Stateful vs stateless inspection
Zones and segmentation
Why organizations use them

Objectives + Scope -> We get a firewall configuration dump (or running configuration export) which can be huge (multiple files, 6k+ lines each)

# Firewall Review Process

> Talk about the logic behind each section -> what each answers

|Section|Question|
|---|---|
|Network Architecture|What am I protecting?|
|Access Control|Who can talk to whom?|
|VPN Security|Who can access the environment remotely?|
|Administrator Authentication|Who can administer the firewall?|
|Monitoring & Logging|How will I know if something goes wrong?|
|Control Plane Protection|Can somebody attack the firewall itself?|

## Network Architecture

Before reviewing FW rules, we first need to understand the network architecture and identify the trust boundaries between different parts of the environment. **A FW review is ultimately an assessment of how traffic is permitted to cross those trust boundaries**.

Reviewing thousands of access control rules without first understanding the underlying architecture can lead to incorrect conclusions and missed findings. This section tries to answer a series of questions.

Let's get right into it!
 
### What Networks Exist?

The first objective of a firewall review is **identifying the networks that make up the environment** and the interfaces (IFs) that connect them. 

These may include user networks, DMZs, public-facing services, etc. Understanding which networks exist provides the context required for the remainder of the review. Without this context, it is difficult to determine whether a FW rule allows legitimate communication or introduces unnecessary risk.


One of the first tasks during a configuration review is therefore **building a high-level map of the environment** and **identifying the role of each network**.

In Cisco ASA/FTD configurations, IFs are typically assigned a logical name using the `nameif` directive. Although the physical interface name identifies the actual interface (e.g. `Port-channel1.100`), the `nameif` usually provides a more useful description of the network connected to it:

{{<figure 
    src="/images/fw-audit-nameif-vs-if.png"
    alt="Listing the logical names of all interfaces."
    width="950"
    caption=""
>}}

### Which Zones Represent Trust Boundaries?

As environments grow, reviewing individual IFs becomes increasingly difficult. To simplify policy management, IFs are often grouped into **security zones**.

A security zone represents a collection of networks with a similar trust level. Rather than applying policies to every individual IF, FWs can enforce controls between zones. For example:
 
| Zone | Purpose |
|--------|--------|
| Public | Untrusted external networks |
| DMZ | Public-facing services |
| Corporate | Internal user networks |

Identifying these zones helps us understand the organisation's trust model and **network segmentation strategy**. In the example below, multiple IFs have been grouped into the same security zone because they share a similar trust level:

{{<figure 
    src="/images/fw-audit-sec-zones.png"
    alt="Listing the configuration's security zones."
    width="950"
    caption=""
>}}

Notice how the `CORPORATE_ZONE` contains the `CORP_USERS`, `CORP_SERVERS`, and `CORP_WIFI` IFs, while the `DMZ_ZONE` contains both `DMZ_WEB` and `DMZ_APP`.

This allows us to reason about traffic flowing between trust levels rather than focusing on individual networks. For example, traffic flowing between the `INTERNET_ZONE` and the `CORPORATE_ZONE` crosses a significant trust boundary and will typically require stricter controls than traffic between networks within the same zone.

### Which Networks are Exposed to the Internet?

One of the first tasks during a firewall review is identifying which IFs are exposed to the internet. These IFs commonly host or terminate:
 
* Public services
* Remote access VPNs
* Site-to-site VPNs
* Published applications

Because they are directly reachable by external users, they typically **represent the highest-risk attack surface** within the environment.

In Cisco ASA/FTD configurations, internet-facing IFs can often be identified through a combination of their logical names (`nameif`), public IP addressing, and their role in VPN termination:

{{<figure 
    src="/images/fw-audit-internet-exposed-pubIps-nameif-vpnTermination.png"
    alt="Enumerating publicly exposed interfaces."
    width="950"
    caption=""
>}}

### Which IFs are used for management?

Management IFs are used by administrators to configure, monitor, and maintain the FW. Common management services include:
 
* SSH
* HTTPS
* TACACS
* RADIUS
* SAML-based administration
 
These IFs should be carefully reviewed as unauthorised access could result in complete compromise of the FW itself.
 
In addition to identifying dedicated management IFs, reviewers should also determine which networks are permitted to access them and whether management traffic is appropriately segregated from user and internet-facing networks.
 
### Trust Boundaries
 
The most important outcome of the Network Architecture review is identifying trust boundaries.
 
A trust boundary exists whenever traffic moves between networks with different security requirements or levels of trust.
 
Examples include:
 
* Internet → Corporate
* Internet → DMZ
* Corporate → Management
* Partner → Corporate
 
These boundaries determine where firewall controls are expected to enforce security policies.
 
Once the architecture and trust boundaries have been identified, we can begin reviewing how traffic is actually permitted to flow between them.
 
This brings us to the most important part of the firewall review: **Access Control**.

## Access Control
## VPN Security
## Administrator Authentication
## Monitoring & Logging
## Control Plane Protection
## Automating the Review with Firewall-Audit



