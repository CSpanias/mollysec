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

Firewall (firewall) reviews are a common component of infrastructure security assessments, yet many practitioners are unfamiliar with how they are performed in practice.

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

Before reviewing firewall rules, we first need to understand the network architecture and identify the trust boundaries between different parts of the environment. **A firewall review is ultimately an assessment of how traffic is permitted to cross those trust boundaries**.

Reviewing thousands of access control rules without first understanding the underlying architecture can lead to incorrect conclusions and missed findings. This section tries to do just that by focusing on the following areas:

|Section|Question|
|---|---|
|Network Identification|Which networks exist?|
|Security Zones|How are networks grouped?|
|Trust Boundaries|How do security zones relate to one other?|
|Publicly Exposed Networks|Which networks are internet-accessible?|
|Management Interfaces|How is firewall administered?|

Let's get right into it!
 
### Network Identification

The first objective of a firewall review is **identifying the networks that make up the environment** and the interfaces (IFs) that connect them. 

These may include user networks, [DMZs](https://www.okta.com/en-gb/identity-101/dmz/), public-facing services, etc. Understanding which networks exist provides the context required for the remainder of the review. Without this context, it is difficult to determine whether a firewall rule allows legitimate communication or introduces unnecessary risk.


One of the first tasks during a configuration review is therefore **building a high-level map of the environment** and **identifying the role of each network**.

In Cisco ASA/FTD configurations, IFs are typically assigned a logical name using the [`nameif`](https://www.grandmetric.com/knowledge-base/design_and_configure/how-to-configure-security-level-and-nameif-on-cisco-asa/) directive. Although the physical interface name identifies the actual interface (e.g. `Port-channel1.100`), the `nameif` usually provides a more useful description of the network connected to it:

{{<figure 
    src="/images/fw-audit-nameif-vs-if.png"
    alt="Listing the logical names of all interfaces."
    width="750"
    caption=""
>}}

### Security Zones

As environments grow, reviewing individual IFs becomes increasingly difficult. To simplify policy management, IFs are often grouped into security zones. **A security zone represents a collection of networks with a similar trust level**. Rather than applying policies to every individual IF, firewalls can enforce controls between zones.

Identifying these zones helps us understand the organisation's trust model and **network segmentation strategy**. In the example below, multiple IFs have been grouped into the same security zone because they share a similar trust level:

{{<figure 
    src="/images/fw-audit-sec-zones.png"
    alt="Listing the configuration's security zones."
    width="750"
    caption=""
>}}

### Trust Boundaries

**Trust boundaries exist whenever traffic moves between zones with different trust levels**. This allows us to reason about traffic flowing between trust levels rather than focusing on individual networks. However, trust boundaries are not explicitly defined in the configuration. Instead, they are identified by analysing how security zones relate to one another and where traffic is expected to move between networks with different trust levels.

Let's see how the security zones identified during our review map to their respective trust levels:

| Zone             | Trust Level        |
| ---------------- | ------------------ |
| INTERNET\_ZONE   | Untrusted          |
| DMZ\_ZONE        | Semi-Trusted       |
| CORPORATE\_ZONE  | Trusted            |
| MANAGEMENT\_ZONE | Highly Trusted     |
| CLOUD\_VPN\_ZONE | External / Partner |

We can infer several trust boundaries requiring review based on the above table, but keep in mind that this is still theoretical (for now). Identifying these boundaries helps us understand **where firewall controls are expected to enforce security policies**.

In general, interesting boundaries involve internet-facing networks, management networks, VPN-connected environments, internal corporate networks, etc. For our sample environment, the following trust boundaries could be of interest:

| Trust Boundary                     |
| ---------------------------------- |
| INTERNET_ZONE ↔ DMZ_ZONE         |
| INTERNET_ZONE ↔ CORPORATE_ZONE   |
| CORPORATE_ZONE ↔ MANAGEMENT_ZONE |
| CORPORATE_ZONE ↔ CLOUD_VPN_ZONE  |

Notice that these boundaries were selected because they represent the most interesting trust transitions within the environment. For now, we are simply identifying areas that require further review; we are not claiming that traffic is permitted between these zones.

For example, although a potential trust boundary may exist between the `INTERNET_ZONE` and the `MANAGEMENT_ZONE`, we would generally not expect direct management access from the internet.  If there is one, that would probaly be the result of poor security design architecture.

> *Confirming whether traffic is actually permitted across these boundaries is part of the next phase: **Access Control**.*

### Publicly Exposed Networks

One of the most important tasks during a firewall review is **identifying which IFs are exposed to the internet**. These IFs commonly host or terminate public services, remote access VPNs, site-to-site VPNs, etc. Because they are directly reachable by external users, they typically **represent the highest-risk attack surface** within the environment.

In Cisco ASA/FTD configurations, internet-facing IFs can often be identified through a combination of their logical names (`nameif`), public IP addressing, and their role in VPN termination:

{{<figure 
    src="/images/fw-audit-internet-exposed-pubIps-nameif-vpnTermination.png"
    alt="Enumerating publicly exposed interfaces."
    width="550"
    caption=""
>}}

### Management Interfaces

Management IFs are used by administrators to configure, monitor, and maintain the firewall. Common management services include SSH and HTTPS, while authentication is often performed using services such as TACACS, RADIUS, or SAML. These IFs should be carefully reviewed as unauthorised access could result in complete compromise of the firewall itself.

We have already seen that our sample configuration includes an IF called `MGMT` which is under the `MANAGEMENT_ZONE` security zone as well as another IF called `management`. In the example below, the firewall's `MGMT` IF can be administered via SSH from the `10.99.99.0/24` and `10.10.10.0/24` networks. This allows us to identify both the management IF and the networks authorised to access it:

{{<figure 
    src="/images/fw-audit-mgmt-ifs.png"
    alt="Enumerating management interfaces."
    width="750"
    caption=""
>}}

At this stage, we have identified the networks that make up the environment, how they are grouped into security zones, where the most important trust boundaries exist, which networks are exposed to the internet, and how the firewall is managed.

We now understand the architecture well enough to answer the next question: **who can talk to whom?**
 
## Access Control

Once the architecture and trust boundaries have been identified, we can begin reviewing how traffic is permitted to flow between them. The objective of this phase is determining **which systems can communicate with one another** and whether those communications align with the organisation's security requirements.

In Cisco firewalls, this is primarily achieved through **Access Control Lists (ACLs)**. ACLs **define which traffic is permitted or denied** as it traverses the firewall and therefore represent one of the most important parts of the configuration. A review of the firewall's ACLs helps answer questions such as:

* Which systems can communicate?
* Which services are allowed?
* Which trust boundaries can be crossed?
* Is access restricted according to the principle of least privilege?
* Are there any overly permissive rules?

### What Are ACLs?

**An ACL is a collection of rules** evaluated by the firewall to determine whether traffic should be permitted or denied. As an example, the below rule permits HTTPS traffic to the `WEB-SERVER` object:

{{<figure 
    src="/images/fw-audit-cisco-acl-syntax.png"
    alt="Enumerating management interfaces."
    width="950"
    caption=""
>}}

Cisco ASA/FTD firewalls support both Standard and Extended ACLs; the latter are more common and can filter traffic based on source, destination, protocol, and port information.

An important consideration is that **ACLs are evaluated from top to bottom**, which makes rule order extremely important. When a packet matches a rule, processing stops and the associated action is applied.

For example, the below order means that traffic destined for `10.10.10.10:22` will be denied because the first rule matches before the second rule is evaluated:

{{<figure 
    src="/images/fw-audit-rule-order.png"
    alt="Enumerating management interfaces."
    width="950"
    caption=""
>}}

A poorly positioned rule can unintentionally override more restrictive controls further down the ACL.

### Permit vs Deny

Every ACL rule ultimately performs one of two actions: `Permit` or `Deny`. Permit rules allow traffic to flow between networks, while deny rules explicitly block communication.

During a review, it is important to understand:

* Which communications have been intentionally permitted/denied.
* Whether the resulting policy reflects the organisation's security requirements.

The ratio of permit and deny rules can also provide insight into the overall design philosophy of the firewall policy.

### The Implicit Deny

One of the most important concepts in firewall security is the implicit deny: **if traffic does not match any ACL entry, the firewall will generally deny the traffic by default**.

Conceptually, every ACL ends with `deny ip any any`, even if that rule is not explicitly configured. This behaviour helps enforce a least-privilege approach where only explicitly permitted traffic is allowed. 

Some organisations choose to configure an explicit `deny ip any any` rule at the end of an ACL to make this behaviour visible and provide additional logging capabilities.

### Any-Any Rules

One of the first checks during an ACL review is the identification of **overly permissive rules** (e.g. `permit ip any any` or `permit tcp any any`).

These rules allow communication between extremely broad groups of systems and can significantly increase the attack surface of the environment. Although there are occasionally legitimate business reasons for broad access, such rules typically warrant additional review and justification.

### Object Groups

Large firewall deployments often contain thousands of individual systems and networks. To simplify policy management, Cisco firewalls support Network Objects, Service Objects, and Object Groups. For example:

`object network WEB-SERVER`
`host 172.16.10.100`

Instead of referencing the IP address directly in ACLs, administrators can reference the object name:

`access-list FW_ACL extended permit tcp any object WEB-SERVER eq 443`

Object groups extend this concept by allowing multiple objects to be grouped together and referenced through a single ACL entry. This improves readability, simplifies maintenance, and reduces the likelihood of configuration errors.

## VPN Security
## Administrator Authentication
## Monitoring & Logging
## Control Plane Protection
## Automating the Review with Firewall-Audit



