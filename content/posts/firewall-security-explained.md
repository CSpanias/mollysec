---
title: "Firewall Security Explained"
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

Once the architecture and trust boundaries have been identified, we can begin reviewing how traffic is permitted to flow between them. The objective of this phase is determining **which systems can communicate with one another** and whether those communications align with the organisation's security requirements. In Cisco firewalls, this is primarily achieved through ACLs.

### Access Control Lists

**Access Control Lists (ACLs) define which traffic is permitted or denied** as it traverses the firewall and therefore represent one of the most important parts of the configuration. Each ACL consists of one or more rules evaluated by the firewall to determine how traffic should be handled.

As an example, the below rule permits HTTPS traffic to the `WEB-SERVER` object:

{{<figure 
    src="/images/fw-audit-cisco-acl-syntax.png"
    alt="Enumerating management interfaces."
    width="950"
    caption=""
>}}

> *Cisco ASA/FTD firewalls support both [Standard and Extended ACLs](https://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23602-confaccesslists.html#toc-hId--2010465938); the latter are more common and can filter traffic based on source, destination, protocol, and port information.*

An important consideration is that **ACLs are evaluated from top to bottom**, which makes rule order extremely important. When a packet matches a rule, processing stops and the associated action is applied. This behaviour is commonly referred to as **first-match processing**.

For example, the below order means that traffic destined for `10.10.10.10:22` will be denied because the first rule matches before the second rule is evaluated:

{{<figure 
    src="/images/fw-audit-rule-order.png"
    alt="Enumerating management interfaces."
    width="950"
    caption=""
>}}

### Objects & Object Groups

Large firewall deployments often contain thousands of individual systems and networks. To simplify policy management, Cisco firewalls support network objects, service objects, and object groups.

Notice that on the first ACL example we saw, the `FW_ACL` references the object name (`WEB-SERVER`) rather than the underlying IP address (`172.16.10.100`). Object groups extend this concept by allowing multiple objects to be grouped together and referenced through a single ACL entry.

This improves readability, simplifies maintenance, and reduces the likelihood of configuration errors.

{{<figure 
    src="/images/fw-audit-network-object-groups.png"
    alt="Creating and using network object groups."
    width="950"
    caption=""
>}}

### Permit vs Deny

Every ACL rule ultimately performs one of two actions: `permit` or `deny`. Permit rules allow traffic to flow between networks, while deny rules explicitly block communication. An important thing to know when reviewing ACLs is the **implicit deny**: if traffic does not match any ACL entry, the firewall will generally deny the traffic by default.

Conceptually, every ACL ends with `deny ip any any`, even if that rule is not explicitly configured. This behaviour helps enforce a least-privilege approach where only explicitly permitted traffic is allowed. Some organisations choose to configure an explicit "deny all" rule at the end of an ACL to make this behaviour visible.

The main thing we look out for here is **overly permissive rules**, such as `permit ip any any` or `permit tcp any any`. These rules allow communication between extremely broad groups of systems and significantly increase the environment's attack surface.

To tie this section together let's look at an example. The first three ACL entries shown below, permit specific communications between defined systems which is how a good ACL looks like. However, they are followed by an overly permissive rule which essentially negates the last explicitly defined "deny all" rule:

{{<figure 
    src="/images/fw-audit-acls.png"
    alt="Examples of various ACL rules."
    width="950"
    caption=""
>}}

Based on the above ruleset, the third ACL entry appears to restrict RDP access to the `DOMAIN-CONTROLLER` from the `JUMP-HOST`. However, the intended restriction is completely negated by the subsequent "allow all" rule; traffic that does not match the third rule will ultimately be permitted by the fourth.

As a result, any host can successfully RDP to the `DOMAIN-CONTROLLER` no problem!

## VPN Security

Virtual Private Networks (VPNs) extend connectivity beyond the local environment and therefore represent some of the most important trust boundaries within the network. They allow users, cloud environments, branch offices, and business partners to securely communicate across untrusted networks such as the Internet.

Cisco ASA/FTD firewalls support two broad VPN categories:
* [Remote Access VPNs](https://docs.manage.security.cisco.com/cdfmc/c_about_ra_vpns.html#!g_ftd_ra_vpns.html) allow individual users to securely connect to corporate resources from external locations.
* [Site-to-Site VPNs](https://docs.manage.security.cisco.com/cdfmc/c_about_ra_vpns.html#!c_about_s2s_vpns.html) connect networks together and are commonly used for cloud connectivity, branch offices, business partners, and third-party service providers.

While both VPN types allow bidirectional communication, Remote Access VPNs connect users to networks, whereas Site-to-Site VPNs connect networks to networks.

{{<figure 
    src="/images/fw-audit-vpn-types.png"
    alt="Different types of VPN connections."
    width="950"
    caption=""
>}}

### Remote Access VPNs

Remote Access VPN users are typically assigned addresses from dedicated VPN pools after successful authentication. The below configuration creates the `MGMT_VPN_POOL` pool and allows VPN clients to be assigned addresses between `192.168.100.10` and `192.168.101.250`:

{{<figure 
    src="/images/fw-audit-vpn-pools.png"
    alt="Remote access VPN pool definition."
    width="950"
    caption=""
>}}

Large numbers of VPN pools may indicate multiple user populations, different geographic regions, or separate third-party access requirements.

### Site-to-Site VPNs

Site-to-Site VPNs are commonly implemented using Virtual Tunnel Interfaces (VTIs). Understanding these connections is critical because **every VPN effectively extends the organisation's trust boundary** beyond the local network. For example, the below configuration allows us to quickly identify several VPN characteristics: 

{{<figure 
    src="/images/fw-audit-site-to-site-vpns.png"
    alt="Site-to-Site VPN pool definition."
    width="650"
    caption=""
>}}

The tunnel's description indicates its purpose (`AZURE-VTI-PRIMARY`), i.e. connectivity between the organisation's internal network and an Azure-hosted environment. The VPN traffic terminates on the `INTERNET` interface before being sent to the remote VPN peer at `20.50.100.10`. It also lets us identify the VPN technology in use, in this case, `ipsec`.

### VPN Termination

The term VPN "termination" can initially seem counterintuitive because the local VPN endpoint is defined using the `source` keyword. In layman's terms a VPN termination point is **the place where the VPN tunnel is established** and **where traffic is encrypted before leaving and decrypted after arriving**.

In the below example, the VPN tunnel is established between the firewall's `INTERNET` interface and the remote Azure VPN Gateway. These two systems act as the local and remote VPN endpoints that form the IPsec tunnel. Traffic exchanged between the two networks is encrypted before entering the IPsec tunnel and decrypted when it reaches the opposite endpoint.

{{<figure 
    src="/images/fw-audit-vpn-termination.png"
    alt="VPN termination interface."
    width="950"
    caption=""
>}}

### Disabled VPNs

Disabled VPNs generally do not introduce active connectivity risks because they cannot pass traffic. However, they often indicate legacy business relationships, incomplete migrations, or obsolete configuration that should be reviewed and removed where appropriate to reduce administrative overhead and configuration complexity.

{{<figure 
    src="/images/fw-audit-disabled-vpns.png"
    alt="An example of an administrative disabled VPN defintion."
    width="650"
    caption=""
>}}

## Administrator Authentication
## Monitoring & Logging
## Control Plane Protection
## Automating the Review with Firewall-Audit



