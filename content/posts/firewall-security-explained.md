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

After the article about [Email Security](https://mollysec.com/posts/email-security-explained/), I thought I would continue the trend of writing about "*boring*" and "*unpopular*" security assessments. I had a close look at various infrastructure-related components that are never discussed in popular "pentesting" courses and one topic immediately stood out: **firewall configuration reviews**.

These are often treated like a checkbox exercise: more like "*let's get it over with*" rather than "*let's dive into it*". After spending some time fiddling with CISCO configurations and documentation, I have to admit that I now find them a bit less boring than I did before. That's progress, isn't?

We will keep things aligned with the *one-level-deeper* philosophy: high-level enough to avoid information overload, but detailed enough to know what we are doing.

Let's dive straight in.

# TL;DR on Firewalls

**A firewall is a security device that controls traffic flowing between networks**. Depending on its configuration, it can permit, deny, translate, inspect, and monitor traffic crossing organisational trust boundaries.

Traditional packet-filtering firewalls make decisions based on packet attributes such as source address, destination address, protocol, and port numbers. Modern firewalls perform **stateful inspection**, tracking active connections and using connection state when evaluating subsequent traffic. For example, return traffic associated with an established connection can typically be permitted without requiring an additional rule.

Firewalls are commonly used to implement **network segmentation** by dividing environments into security zones such as Internet, Corporate, DMZ, Management, and Cloud. Traffic moving between these zones can then be controlled using ACLs, security policies, NAT, VPNs, and other security controls.

From a security perspective, a firewall serves three primary purposes:

* Enforcing network segmentation
* Restricting communication between trust boundaries
* Monitoring and auditing network activity

In practice, firewall reviews are often performed using configuration dumps or running-configuration exports that can span thousands of lines. The goal of this article is to identify and extract the information that is most relevant to security. Although the examples are based on Cisco ASA/FTD syntax, the concepts discussed are universal for all devices.

# Firewall Review Process

## Overview

This article is split into eight "*review areas*" covering (what I think are) the most relevant to security components of a firewall configuration. While the examples focus on Cisco ASA/FTD configurations, the underlying concepts are vendor-agnostic, so you should have no problem applying them to other devices, such as Fortinet, Palo Alto, etc.

| Section                      | Security Question                                                  |
| ---------------------------- | ------------------------------------------------------------------ |
| Network Architecture         | What assets and trust boundaries am I protecting?                  |
| Access Control               | Who can communicate across those trust boundaries?                 |
| VPN Security                 | Which external users and networks can access the environment?      |
| Administrator Authentication | Who can administer the firewall and how are they authenticated?    |
| Control Plane Protection     | Can untrusted systems communicate directly with the firewall?      |
| Logging                      | Can security events and administrative actions be investigated?    |
| Monitoring                   | Can security or operational issues be detected in a timely manner? |
| NAT                          | Which internal services and networks are exposed externally?       |

## Network Architecture

**A firewall review is ultimately an assessment of how traffic is permitted to cross those trust boundaries**. And to assess something (effectively), we first need to undestand what we are dealing with. In this case, understand the network architecture and identify the trust boundaries between the environment's different parts.

### Networks & Interfaces

Let's start by identifying the networks that make up the environment and the interfaces (IFs) that connect them. These may include user networks, [DMZs](https://www.okta.com/en-gb/identity-101/dmz/), and public-facing services, among others. Understanding which networks exist provides the context required for the remainder of the review. Without this context, it is difficult to determine whether a firewall rule allows legitimate communication or introduces unnecessary risk.

In Cisco ASA/FTD configurations, IFs are typically assigned a logical name using the [`nameif`](https://www.grandmetric.com/knowledge-base/design_and_configure/how-to-configure-security-level-and-nameif-on-cisco-asa/) directive. Although the physical interface name identifies the actual interface (e.g. `Port-channel1.100`), the `nameif` usually provides a more useful description of the network connected to it:

{{<figure 
    src="/images/fw-audit-nameif-vs-if.png"
    alt="Listing the logical names of all interfaces."
    width="750"
    caption=""
>}}

By just doing that, we can see that this environment is pretty-well segmented as there are clearly defined areas: Internet, Corporate, DMZ, Management, etc.

### Security Zones

As environments grow, reviewing individual IFs becomes increasingly difficult. To simplify policy management, IFs are often grouped into security zones. **A security zone represents a collection of networks with a similar trust level**.

Rather than applying policies to every individual IF, firewalls can enforce controls between zones.

Identifying these zones helps us understand the organisation's trust model and **network segmentation strategy**. In the example below, multiple IFs have been grouped into the same security zone because they share a similar trust level:

{{<figure 
    src="/images/fw-audit-sec-zones.png"
    alt="Listing the configuration's security zones."
    width="750"
    caption=""
>}}

We are now seeing a more high-level segmentation defined: "DMZ stuff", "Corporate stuff", "Cloud stuff", etc. which indicates that are probably rules applied on the security zones rather than individual IFs. That's good because we will make our life easier!

### Trust Boundaries

**Trust boundaries exist whenever traffic moves between zones with different trust levels**, for example, between `CORPORATE` and `INTERNET`. These help us to reason about traffic flowing between trust levels rather than focusing on individual networks.

The thing is that trust boundaries are not explicitly defined in the configuration. Instead, they are identified by analysing **how security zones relate to one another** and **where traffic is expected to move** between networks. 

In our example, we could map the identified security zones to their respective trust levels:

| Zone             | Trust Level        | Reason |
| ---------------- | ------------------ | ------ |
| `INTERNET_ZONE`   | Untrusted          | Publicly Exposed |
| `DMZ_ZONE`        | Semi-Trusted       | Internal But |
| `CORPORATE_ZONE`  | Trusted            | Internal |
| `MANAGEMENT_ZONE` | Highly Trusted     | Internal & Restricted |
| `CLOUD_VPN_ZONE` | External / Partner | Third-Party, Not In Our Control |

We can infer several trust boundaries requiring review based on the above table, but keep in mind that this is still theoretical (for now). Identifying these boundaries helps us understand **where firewall controls are expected to enforce security policies**.

In general, interesting boundaries involve internet-facing networks, management networks, VPN-connected environments, internal corporate networks, etc. For our sample environment, the following trust boundaries could be of interest:

| Trust Boundary                     |
| ---------------------------------- |
| `INTERNET_ZONE` ↔ `DMZ_ZONE`         |
| `INTERNET_ZONE` ↔ `CORPORATE_ZONE`   |
| `CORPORATE_ZONE` ↔ `MANAGEMENT_ZONE` |
| `CORPORATE_ZONE` ↔ `CLOUD_VPN_ZONE`  |

Notice that these boundaries were selected because they represent the most interesting trust transitions within the environment. For now, we are simply identifying areas that require further review; we are not claiming that traffic is permitted between these zones. We know nothing about that yet!

For example, we might find a trust boundary between the `INTERNET_ZONE` and the `MANAGEMENT_ZONE`, which would probaly be the result of poor security design architecture and a finding on our report as we wouldn't expect a management-related IF to be publicly exposed!

> *Confirming whether traffic is actually permitted across these boundaries is part of the review area: **Access Control**.*

### Publicly Exposed Networks

Speaking of publicly exposed IFs, that's one of the most interesting configurations to search for. These IFs commonly host or terminate public services, remote access VPNs, site-to-site VPNs, etc. and **they represent the highest-risk attack surface** within the environment.

In Cisco ASA/FTD configurations, internet-facing IFs can often be identified through a combination of their logical names (`nameif`), public IP addressing, and their role in VPN termination:

{{<figure 
    src="/images/fw-audit-internet-exposed-pubIps-nameif-vpnTermination.png"
    alt="Enumerating publicly exposed interfaces."
    width="650"
    caption=""
>}}

On the above screenshot, the logical naming of the `INTERNET` interface makes it pretty clear what its role is. In addition, we can also see that it is also a VPN termination endpoint (more on that later).

### Management Interfaces

Management interfaces are used by administrators to configure, monitor, and maintain the firewall using services hosted on the firewall device itself, such as SSH and HTTPS.These interfaces must be very well protected as unauthorised access could result in complete compromise of the firewall itself.

> *We will see how administrators authenticate to the firewall in the [Administration Authentication](https://mollysec.com/posts/firewall-security-explained/#administrator-authentication) section.*

Our sample config includes two management-related interfaces: `management` and `MGMT`. In the example below, the latter can be administered via SSH from the two specified networks which allows us to identify both the management interfaces and the networks authorised to access it:

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

Cisco ASA/FTD firewalls support Remote Access VPN connectivity through WebVPN, a feature that allows users to establish VPN sessions using a web browser or dedicated VPN client. The configuration below enables the WebVPN service on the `INTERNET` interface, defines the TLS encryption policy used to protect VPN traffic, and enables additional security controls to help secure the VPN portal:

{{<figure 
    src="/images/fw-audit-webvpn.png"
    alt="A sample WebVPN configuration."
    width="650"
    caption=""
>}}

WebVPN is designed to provide secure access for individual users. As a result, reviewing WebVPN configurations often focuses on which interfaces expose the VPN portal, which authentication mechanisms are used, whether Multi-Factor Authentication (MFA) is enforced, which VPN pools are assigned to users, and which internal resources are accessible after connection.

Because WebVPN services are commonly exposed to the Internet, they often represent one of the most accessible entry points into the environment and should therefore receive particular attention during a firewall review.

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

## Control Plane Protection

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

## Logging

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

## Monitoring

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

## Network Address Translation

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



