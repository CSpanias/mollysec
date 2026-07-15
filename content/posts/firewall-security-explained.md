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

After the article about [Email Security](https://mollysec.com/posts/email-security-explained/), I thought I would continue the trend of writing about "*boring*" and "*unpopular*" security assessments. While looking at various infrastructure-related components that are never discussed in popular "pentesting" courses, one topic immediately stood out: **firewall configuration reviews**.

These are often treated like a checkbox exercise: more like "*let's get it over with*" than "*let's dive into it*". After spending some time fiddling with Cisco configurations and documentation, I have to admit that I now find them a bit less boring than I did before. That's progress, isn't?

Let's dive straight in.

# TL;DR on Firewalls

A firewall is simply **a security device that controls traffic flowing between networks**.

Firewalls are commonly used to implement **network segmentation** by dividing environments into security zones (e.g. Public and Internal networks). Traffic moving between these zones can then be controlled using various security controls, such as Access Control Lists (ACLs), Network Address Translation (NAT), and Virtual Private Networks (VPNs).

From a security perspective, a firewall serves three primary purposes:

* Enforcing network segmentation
* Restricting communication across trust boundaries
* Monitoring and auditing network activity

Now that we know what a firewall is, let's see how we can audit one.

# Firewall Review Process Overview

In practice, firewall reviews are often performed using configuration dumps. The client sends us one or more huge file(s) (often 5-6k lines each) and we have to make sense of it. Therefore, our goal is not to analyse every single line individually, but rather **identify and extract the information most relevant to security**.

This article is split into eight "*review areas*" covering the most security-relevant components of a firewall configuration. While the examples focus on Cisco ASA/FTD configurations, the underlying concepts are vendor-agnostic, so you should have no problem applying them to other devices, such as Fortinet, Palo Alto, etc.

| Section                      | Security Question                                                  |
| ---------------------------- | ------------------------------------------------------------------ |
| Network Architecture         | What assets and trust boundaries am I protecting?                  |
| Access Control               | Who can communicate across those trust boundaries?                 |
| VPN Security                 | Which external users and networks can access the environment?      |
| Administrator Authentication | Who can administer the firewall and how are they authenticated?    |
| Control Plane Protection     | Can untrusted systems communicate directly with the firewall?      |
| Logging                      | Can security events and administrative actions be investigated?    |
| Monitoring                   | Can security/operational issues be detected before they impact the environment? |
| NAT                          | Which internal services and networks are exposed externally?       |

# Network Architecture

A firewall audit is **an assessment of how traffic is permitted to cross the specified trust boundaries**. Before we can (effectively) assess anything, we first need to understand the environment they are meant to protect. This means identifying the network architecture and the trust boundaries between its different parts.

Let's start with some definitions:
- A network is **a collection of systems that share a common address space** and can communicate with one another. Networks are typically organised according to their purpose, for example, different networks for corporate users, servers, and public-facing services.
- An interface is **the point where a firewall connects to a network**. Each interface represents a separate segment of the environment and acts as a gateway through which traffic enters or leaves the firewall.

A firewall sits between multiple networks and controls how traffic is permitted to flow between them. For example, one interface may connect to the Internet while another connects to a Corporate network.

Having said that, it makes sense that the first step of a firewall audit is identifying the networks that make up the environment and the interfaces that connect them. Without this context, it is difficult to determine whether a firewall rule has a reason to be there or it just introduces unecessary risk.

In Cisco ASA/FTD configurations, interfaces are assigned a logical name using the [`nameif`](https://www.grandmetric.com/knowledge-base/design_and_configure/how-to-configure-security-level-and-nameif-on-cisco-asa/) directive. Although the physical interface name identifies the actual interface (e.g. `Port-channel1.100`), the `nameif` usually provides a more useful description of the network connected to it:

{{<figure 
    src="/images/fw-audit-nameif-vs-if.png"
    alt="Listing the logical names of all interfaces."
    width="750"
    caption=""
>}}

By just reviewing the interface names, we can already build a high-level understanding of the environment. In this case, the network appears to be pretty-well segmented, with clearly defined areas for internet access, corporate systems, DMZ services, and management networks.

As environments grow, applying policies to and reviewing individual interfaces becomes increasingly difficult. To address this problem, interfaces are often grouped into **security zones**. Simply put, **security zones are collections of networks with a similar trust level**.

Rather than applying policies to every individual interface, firewalls can enforce controls between zones. In the example below, we can already see a bit of a higher-level segmentation strategy compared to just looking at interfaces:

{{<figure 
    src="/images/fw-audit-sec-zones.png"
    alt="Listing the configuration's security zones."
    width="750"
    caption=""
>}}

So far we have networks, interfaces that connects the firewall to them, and groups of interfaces called security zones. Next, we have **trust boundaries**. These exist **whenever traffic moves between zones with different trust levels**, for example, between `CORPORATE` and `INTERNET`.

It is worth noting that trust boundaries are not explicitly defined in the configuration. We have to manually identify them by analysing **how security zones relate to one another** and **where traffic is expected to move** between networks. In our sample configuration, we might have the following security zone to trust level mapping:

| Zone             | Trust Level        | Reason |
| ---------------- | ------------------ | ------ |
| `INTERNET_ZONE`   | Untrusted          | Publicly exposed |
| `DMZ_ZONE`        | Semi-trusted       | Links external and internal |
| `CORPORATE_ZONE`  | Trusted            | Internal |
| `MANAGEMENT_ZONE` | Highly trusted     | Internal and restricted |
| `CLOUD_VPN_ZONE` | External / Partner | Third-party, not under our control |

Based on the above table, we can infer several trust boundaries requiring review. However, keep in mind that this is all purely theoretical. What identifying these boundaries does, is help us understand **where firewall controls are expected to enforce security policies**.

Interesting boundaries typically involve internet-facing networks, management networks, VPN-connected environments, etc. In our example, the following trust boundaries could be of interest:

| Trust Boundary                     |
| ---------------------------------- |
| `INTERNET_ZONE` ↔ `DMZ_ZONE`         |
| `CORPORATE_ZONE` ↔ `MANAGEMENT_ZONE` |
| `CORPORATE_ZONE` ↔ `CLOUD_VPN_ZONE`  |

Remember that we are simply identifying areas that require further review; we are not claiming that traffic is permitted between these zones. We know nothing about that yet!

For example, although we don't expect to be one, we might find a trust boundary between the `INTERNET_ZONE` and the `MANAGEMENT_ZONE`, i.e. a publicly exposed management-related interface.

**Management interfaces** are used by administrators to configure, monitor, and maintain the firewall using services hosted on the firewall device itself, such as SSH and HTTPS. These must be very well protected as unauthorised access could result in complete compromise of the firewall.

On the other hand, **publicly exposed interfaces** typically host or terminate public services, remote access/site-to-site VPNs, etc. These **represent the highest-risk attack surface** within the environment and they can often be identified through a combination of their logical names (`nameif`), public IP addressing, and their role in VPN termination:

{{<figure 
    src="/images/fw-audit-internet-exposed-pubIps-nameif-vpnTermination.png"
    alt="Enumerating publicly exposed interfaces."
    width="650"
    caption=""
>}}

At this stage, we understand the environment well enough to identify the major trust boundaries, which systems are exposed to the Internet, and how administrators manage the firewall. We can now move from *what the environment looks like* to *how communication is controlled within it* and answer the next question: **who can talk to whom?**
 
## Access Control

Once we understand the environment's architecture, we can begin reviewing how traffic is permitted to flow within it. The objective of this phase is determining **which systems can communicate with one another** and whether those communications align with the organisation's security requirements. In Cisco firewalls, this is primarily achieved through **Access Control Lists (ACLs)**, which define the conditions under which traffic is permitted or denied.

An ACL is a collection of rules used to decide whether traffic should be allowed or denied. Because ACLs determine which systems can communicate across trust boundaries, they represent one of the most important areas of any firewall review. For instance, the below rule permits HTTPS traffic to the `WEB-SERVER` object:

{{<figure 
    src="/images/fw-audit-cisco-acl-syntax.png"
    alt="Enumerating management interfaces."
    width="950"
    caption=""
>}}

> *Cisco ASA/FTD firewalls support both [Standard and Extended ACLs](https://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23602-confaccesslists.html#toc-hId--2010465938). The ACL shown above is the latter and are generally more common as they can filter traffic based on source, destination, protocol, and port information.*

An important consideration about ACLs is what is known as **first-match processing**. ACLs are evaluated from top to bottom, which makes rule order extremely important. When a packet matches a rule, processing stops and the associated action is applied.

For example, the rule order below causes traffic destined for `10.10.10.10:22` to be denied because the first matching rule is applied before the second rule is evaluated:

{{<figure 
    src="/images/fw-audit-rule-order.png"
    alt="Enumerating management interfaces."
    width="950"
    caption=""
>}}

Large firewall deployments often contain thousands of systems, networks, and services. To simplify management, Cisco firewalls support network objects, service objects, and object groups.

Think of a **network object** as a named reference (e.g. `WEB-SERVER`) to an IP address or network (e.g. `172.16.10.100`). **Object groups** extend this concept by allowing multiple objects to be grouped together and referenced through a single ACL entry.

{{<figure 
    src="/images/fw-audit-network-object-groups.png"
    alt="Creating and using network object groups."
    width="950"
    caption=""
>}}

Every ACL rule ultimately performs one of two actions: `permit` (allow network traffic) or `deny` (block network traffic). Because firewalls are designed with the principle of least privilege in mind, if traffic is not explicitly permitted, i.e. does not match any ACL entry, it will be denied by default. This is known as **implicit deny** and means that every ACL effectively ends with `deny ip any any`, even when that rule does not explicitly appear in the configuration.

When reviewing ACLs, one of the first things we look for is the presence of **overly permissive rules**, such as `permit ip any any` or `permit tcp any any`. These rules allow communication between extremely broad groups of systems and can significantly **increase the environment's attack surface**.

In the example below, the first three ACL entries permit specific communications between explicitly defined systems. However, the fourth rule permits all remaining traffic, effectively undermining the restrictions introduced by the preceding rules:

{{<figure 
    src="/images/fw-audit-acls.png"
    alt="Examples of various ACL rules."
    width="950"
    caption=""
>}}

We reached the point where we understand which systems are permitted to communicate across the identified trust boundaries and whether those permissions appear appropriately restricted. We can now move beyond internal communications and examine another important question: **who can access the environment remotely?**

# VPN Security

Virtual Private Networks (VPNs) extend connectivity beyond the local environment and therefore represent some of the most important trust boundaries within a network. They allow users, cloud environments, branch offices, business partners, and third-party service providers to securely communicate across untrusted networks such as the Internet.

From a security perspective, every VPN introduces a pathway into or out of the environment and therefore warrants careful review.

Cisco ASA/FTD firewalls support two broad VPN categories:
* [Remote Access VPNs](https://docs.manage.security.cisco.com/cdfmc/c_about_ra_vpns.html#!g_ftd_ra_vpns.html) allow individual users to securely connect to corporate resources from external locations.
* [Site-to-Site VPNs](https://docs.manage.security.cisco.com/cdfmc/c_about_ra_vpns.html#!c_about_s2s_vpns.html) connect networks together and are commonly used for cloud connectivity, branch offices, business partners, and third-party service providers.

{{<figure 
    src="/images/fw-audit-vpn-types.png"
    alt="Different types of VPN connections."
    width="950"
    caption=""
>}}

**Remote Access VPNs** provide individual users with secure access to internal resources. After successful authentication, users are typically assigned addresses from dedicated VPN pools:

{{<figure 
    src="/images/fw-audit-vpn-pools.png"
    alt="Remote access VPN pool definition."
    width="950"
    caption=""
>}}

Cisco ASA/FTD firewalls also support Remote Access VPN connectivity through **WebVPN**, a feature that allows users to establish VPN sessions using a web browser or dedicated VPN client. WebVPNs often represent one of the most accessible entry points into the environment. Because they are commonly exposed to the Internet and designed for use by remote users, they require particular attention during a security review.

{{<figure 
    src="/images/fw-audit-webvpn.png"
    alt="A sample WebVPN configuration."
    width="650"
    caption=""
>}}

**Site-to-Site VPNs** are commonly implemented using Virtual Tunnel Interfaces (VTIs). Understanding these connections is critical because every Site-to-Site VPN effectively extends the organisation's trust boundary beyond the local network.

{{<figure 
    src="/images/fw-audit-site-to-site-vpns.png"
    alt="Site-to-Site VPN pool definition."
    width="650"
    caption=""
>}}

The term **VPN "termination"** can initially seem counterintuitive because the local VPN endpoint is defined using the `source` keyword. In layman's terms, a VPN termination point is **the place where the VPN tunnel is established** and **where traffic is encrypted before leaving and decrypted after arriving**.

In the below example, the VPN tunnel is established between the firewall's `INTERNET` interface and the remote Azure VPN Gateway. These two systems act as the local and remote VPN endpoints that form the IPsec tunnel. Traffic exchanged between the two networks is encrypted before entering the IPsec tunnel and decrypted when it reaches the opposite endpoint.

{{<figure 
    src="/images/fw-audit-vpn-termination.png"
    alt="VPN termination interface."
    width="950"
    caption=""
>}}

While **disabled VPNs** generally do not introduce active connectivity risks because they cannot pass traffic, they often indicate legacy business relationships, incomplete migrations, or obsolete configuration. Their presence may also reveal previously trusted external connections that should be reviewed and removed where appropriate to reduce administrative overhead and configuration complexity.

{{<figure 
    src="/images/fw-audit-disabled-vpns.png"
    alt="An example of an administrative disabled VPN defintion."
    width="650"
    caption=""
>}}

We now understand which users, networks, and external organisations can access the environment remotely. We can now shift gears and answer another important question: **who can administer the firewall?**

# Administrator Authentication

Firewalls sit at the centre of the network and often provide direct access to critical infrastructure. As a result, reviewing how administrators authenticate to the device is just as important as reviewing the firewall policies themselves. A weak authentication configuration can allow an attacker to bypass all other security controls and gain full administrative control of the firewall.

Cisco ASA/FTD firewalls support several mechanisms for handling Authentication, Authorisation, and Accounting (AAA). The primary objective of these mechanisms is centralising authentication decisions rather than maintaining separate local accounts on every device. The most common protocols are:

* [Terminal Access Controller Access Control System (TACACS+)](https://www.cisco.com/web/fw/tools/cisco-business/emulators/switch/catalyst/c1300-24mgp-4x/html/cat1k/english/1300/t_management_access_authentication.html#!t_tacacs_client.html) is one of the most common authentication protocols used for Cisco device administration. AAA decisions are delegated to dedicated TACACS+ servers.
* [Remote Authentication Dial-In User Service (RADIUS)](https://www.cisco.com/web/fw/tools/cisco-business/emulators/switch/catalyst/c1300-24mgp-4x/html/cat1k/english/1300/t_management_access_authentication.html#!radius-client.html) provides a similar centralised authentication model and is commonly used for network device administration, VPN authentication, and wireless access control.
* [Security Assertion Markup Language (SAML)](https://www.cisco.com/site/us/en/learn/topics/security/what-is-saml.html) integrates the firewall with external identity providers such as Microsoft Entra ID, Okta, and Ping Identity. Rather than authenticating directly against the firewall, administrators and VPN users are redirected to a trusted identity provider. This enables capabilities such as Single Sign-On (SSO), Multi-Factor Authentication (MFA), and centralised identity management.

In many environments, these protocols are backed by dedicated AAA platforms such as [Cisco Identity Services Engine (ISE)](https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/admin_guide/b_ise_admin_3_4/b_ISE_admin_overview.html#concept_vt3_bbb_1kb), Microsoft Network Policy Server (NPS), or FreeRADIUS. Rather than authenticating users locally, the firewall forwards authentication requests using TACACS+ or RADIUS to one of these platforms. The AAA platform then validates the user's identity against a central identity source such as Active Directory, LDAP, or Microsoft Entra ID and returns the appropriate authentication and authorisation decision.

While ISE is Cisco's enterprise AAA solution, NPS and FreeRADIUS provide similar centralised authentication capabilities and are commonly encountered in mixed-vendor environments.

The takeaway here is that TACACS+ and RADIUS are protocols that define how the firewall communicates with a centralised authentication system, while TACACS+, RADIUS, ISE, NPS, or FreeRADIUS are AAA servers/platforms that receive those requests and make the actual AAA decisions:


{{<figure 
    src="/images/fw-audit-admin-auth.png"
    alt="A diagram depicting the authentication flow in CICSO environments."
    width="950"
    caption=""
>}}

Smaller environments often authenticate directly against dedicated TACACS+ or RADIUS servers. Larger environments commonly introduce AAA platforms such as Cisco ISE, Microsoft NPS, or FreeRADIUS, which in turn integrate with central identity stores such as Active Directory, Microsoft Entra ID, or LDAP.

Before we move onto the next section, let's see a sample configuration and how the respective authentication flow would look like:

{{<figure 
    src="/images/fw-audit-admin-auth-flow-config.png"
    alt="An example TACACS+ configuration."
    width="750"
    caption=""
>}}

{{<figure 
    src="/images/fw-audit-admin-auth-flow.png"
    alt="A diagram depicting the authentication flow in CICSO environments."
    width="950"
    caption=""
>}}

Regardless of the protocol used, the goal remains the same: centralising AAA, improving auditability, and reducing reliance on local administrator accounts. The objective here is determining **whether administrative access to the firewall is appropriately controlled, monitored, and auditable**.

# Control Plane Protection

Up to this point we have primarily focused on traffic flowing *through* the firewall (data plane), and not **how traffic is permitted to reach the firewall itself** (control plane). The latter includes operations like management, monitoring, routing, and VPN-related services. 

Protecting the control plane ensures that only authorised systems can communicate directly with the firewall. Services such as SSH, HTTPS, and SNMP are hosted directly on the device and therefore form part of its control plane. If these services are exposed to untrusted networks, an attacker may be able to target the firewall directly rather than attempting to traverse it.

{{<figure 
    src="/images/fw-audit-control-vs-data-plane.png"
    alt="The difference between the control plane and data plane."
    width="750"
    caption=""
>}}

One thing we can review is **which hosts/networks are permitted to access administrative services**. In the below configuration, systems within the two defined networks to establish SSH sessions to the firewall's `MGMT` interface:

{{<figure 
    src="/images/fw-audit-ssh-management-access.png"
    alt="Reviewing access to the firewall's administrative services."
    width="450"
    caption=""
>}}

When reviewing these entries, we should verify that access is limited to legitimate management networks and not unnecessarily exposed to broader user populations.

Cisco firewalls can also apply ACLs to the control plane itself. In the example below, the `CONTROL_PLANE_BLOCK` ACL is first defined using the `access-list` keyword and then applied using the `access-group` keyword:

{{<figure 
    src="/images/fw-audit-control-plane-acl.png"
    alt="Definition and application of a contol-plane ACL."
    width="750"
    caption=""
>}}

The `control-plane` option **changes the scope of the ACL from traffic traversing the firewall to traffic destined to the firewall itself**. As a result, all IP traffic arriving on the `INTERNET` interface and destined to services hosted on the firewall would be denied:

A Control Plane ACL only affects traffic destined to services hosted directly on the firewall. Traffic traversing the firewall continues to be processed by the normal data-plane ACLs. In the example above, direct access to the firewall is blocked, while traffic passing through the firewall towards internal resources remains unaffected.

{{<figure 
    src="/images/fw-audit-control-vs-data-plane-diagram.png"
    alt="A diagram of the difference between the contol plane and the data plane."
    width="950"
    caption=""
>}}

This allows organisations to explicitly define which hosts and networks may access management services hosted on the firewall. **The goal is to ensure that only authorised administrators and monitoring systems can communicate directly with the firewall itself**.

# Logging

Firewall rules determine which traffic is permitted, VPNs determine who can access the environment remotely, and authentication controls determine who can administer the device. None of these controls are particularly useful if security events cannot be observed and investigated.

Logging provides **visibility into firewall activity** and creates an **audit trail of security-relevant events**. During an incident, firewall logs are often one of the primary sources of evidence used to understand what happened, which systems were involved, and whether suspicious activity occurred.

The objective of this phase is determining whether logging is enabled, where logs are being sent, which systems receive security events, and whether sufficient information is available for incident investigations.

One of the primary goals of logging is **centralisation**. Instead of reviewing events separately on every firewall, router, switch, and server, organisations typically collect logs into a dedicated logging platform (Syslog server) or Security Information and Event Management (SIEM) solution. 

Depending on the configuration, firewalls can generate logs for a wide range of activities, such as ACL matches, administrative actions, configuration changes, etc. Centralised logging improves visibility, simplifies investigations, and helps correlate events across multiple systems.

The below sample configuration enables logging and forwards events to the specified Syslog server:

{{<figure 
    src="/images/fw-audit-syslog-server.png"
    alt="A sample configuration of a Syslog server."
    width="650"
    caption=""
>}}

At the end of the day, the goal of logging is to **ensure that security-relevant events can be captured, retained, and investigated when required**.

# Monitoring

While logging helps investigate events after they occur, **monitoring helps identify issues as they happen**. Effective monitoring allows administrators to track the health, performance, and availability of the firewall and receive alerts when abnormal conditions are detected. From our (security) perspective, we mostly care about the latter, i.e. alerts when the firewall becomes unavailable, the VPN tunnel fails, there is unusually high CPU utilisation, etc. 

The objective of this phase is determining whether the firewall is actively monitored, which monitoring systems receive alerts, whether operational issues can be detected quickly, and whether sufficient visibility exists into the firewall's health and status.

Cisco ASA/FTD firewalls commonly use the Simple Network Management Protocol (SNMP) to integrate with monitoring platforms. For example, the below configuration allows the monitoring server at `10.99.99.220` to collect information from the firewall using SNMP:

{{<figure 
    src="/images/fw-audit-snmp-server.png"
    alt="A sample configuration of an SNMP server."
    width="650"
    caption=""
>}}

Monitoring is often centralised through dedicated monitoring platforms, such as SolarWinds, PRTG, Zabbix, etc. Security teams may also integrate monitoring data into SIEM platforms alongside firewall logs.

Ultimately, the goal is ensuring that operational issues affecting the firewall can be detected, investigated, and resolved before they impact the wider environment.

# Network Address Translation

Network Address Translation (NAT) modifies packet addresses as traffic traverses the firewall. Although NAT is not a security control by itself, reviewing NAT policies helps us understand how internal systems communicate with external networks and which services are exposed beyond the organisation's trust boundaries.

Therefore, it can help us identify which networks can access the Internet, which internal systems are publicly accessible, how traffic moves across trust boundaries, and whether NAT aligns with the architecture identified earlier.

There are two common forms of NAT:
* **Dynamic NAT (PAT)** &rarr; many internal systems share a single public IP address.
* **Static NAT** &rarr; a fixed mapping between an internal and external address.

> *Dynamic NAT is often implemented as Port Address Translation (PAT) where multiple internal systems share a single public IP address, with the firewall using source port numbers to keep individual connections separate.*

The below Dynamic NAT rule translates traffic originating from the `CORPORATE` network to the IP address assigned to the `INTERNET` interface; this type of NAT is commonly used to provide Internet access for internal users and servers. The Static NAT rule has traffic arriving at the public address associated with the `INTERNET` interface is translated to the internal `WEB-SERVER`:

{{<figure 
    src="/images/fw-audit-nat.png"
    alt="Dynamic versus Static NAT configuration."
    width="650"
    caption=""
>}}

When reviewing static NAT rules, we should identify which systems are being exposed and whether the exposure is justified.

A common misconception is that NAT alone controls access between networks. In reality, NAT and ACLs perform different functions: NAT determines how traffic is translated, while ACLs determine whether the traffic is permitted. **NAT does not automatically permit Internet access**.

Both controls must usually be considered together when reviewing traffic flows.

# Automating the Review with Firewall-Audit