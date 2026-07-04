---
title: "LLMNR/NBT-NS Poisoning Explained"
date: "2026-06-20"
author: "mollysec"
description: "How legacy name resolution protocols work and why they still persist more than 40 years later."
featured: true
tags: ["LLMNR","NBT-NS","NBNS","mDNS","Poisoning","Responder","AitM"]
categories: []
series: ""
draft: false
---

# Introduction

**LLMNR/NBT-NS Poisoning** is one of the most consistent vulnerabilities I come across during internal tests. Even if the name does not ring a bell, chances are you have, at some point in a lab, launched [`Responder`](https://github.com/lgandx/Responder) hoping to capture a hash:

{{<figure 
    src="/images/poisoning-responder-example.png"
    alt="A screenshot of running Responder and capturing an NTLMv2 hash."
    width="700"
    caption=""
>}} 

If that's the case, you are already familiar with the attack, but have never really taken the time to explore what is actually happening behind the scenes. Under the right conditions, this attack vector can result in getting an NTLMv2 hash which can be recovered or relayed (e.g. combined with something such as the lack of SMB signing). It can be our way from:
- Unauthenticated &rarr; domain foothold
- Standard user &rarr; standard user (lateral movement)
- Standard user &rarr; privileged user (privilege escalation)

I have been lucky enough to get and then recover a Domain Admin (DA)'s hash this way; achieving full domain compromise in just a couple of hours!

In this article we will go over what these protocols are, how they work, and why they are still here to this day. But before diving into the nitty gritty details for each protocol, we will first go through a high-level overview of how name resolution works within a Windows domain.

# TL;DR on DNS

We won't go through any details about the Domain Name System (DNS) here, but if you need a quick refresher these two short articles will do the job:
- [DNS 101: Introduction to the Domain Name System](https://www.scoutdns.com/library/dns-101-introduction/)
- [How DNS Resolution Works (At a High Level)](https://www.scoutdns.com/library/how-dns-resolution-works/).

The layman's version is that DNS is the link between the way humans communicate with computers and the way computers communicate with each other. For example:
1. A user types `example.com` on the browser.
2. The computer will ask a translator (name resolution protocol) to resolve the hostname (`example.com`) to an IP address.
3. The translator will resolve the hostname to an IP address (e.g. `132.34.45.121`) and send it back to the user.

{{<figure 
    src="/images/dns-resolution.png"
    alt="The process of DNS resolution."
    width="650"
    caption="Image taken from [here](https://www.geeksforgeeks.org/computer-networks/address-resolution-in-dns-domain-name-server/)."
>}} 

So let's now see where these legacy name resolution protocols (LLMNR, mDNS, and NBT-NS) come into the picture.

In every functional domain, there is a [DNS server](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-overview) which is responsible for the name resolution process we just described. However, DNS can fail for various reasons, such as using single-label hostnames vs fully qualified domain names (FQDN) (e.g. `FS01` vs `FS01.MOLLYSEC.COM`), unreachable or misconfigured DNS servers, hosts that are not registered in DNS, etc.

In the case of a DNS failure, these legacy protocols kick in to save the day. They act as a fallback mechanism and their job is to resolve the hostname locally, for instance, by asking every other host (or a specific group of hosts) on the local area network (LAN) if they know who `FS01` is. This is what is called **Local Name Resolution**.

On Windows systems, name resolution follows a hierarchical order:

1. First, the DNS server will be asked to resolve a hostname, URL, UNC path, etc.
2. If the DNS fails, LLMNR (and mDNS in some cases) will be queried.
3. If LLMNR also fails, NBT-NS may be used as a last resort.

These fallback protocols rely on [broadcast](https://www.pynetlabs.com/difference-between-broadcast-and-multicast/#elementor-toc__heading-anchor-2) (ask all LAN hosts) or [multicast](https://www.pynetlabs.com/difference-between-broadcast-and-multicast/#elementor-toc__heading-anchor-7) (ask only a group of hosts) queries. In the below example, when DNS fails between `WK02` and the DNS server due to the usage of a single-label name, the former uses a broadcast query. The first host to respond is assumed to be the correct one.

{{<figure 
    src="/images/dns-resolution-protocols.png"
    alt="The process of name resolution in Windows."
    width="950"
    caption=""
>}}

The issue with these query types is that they can be [easily intercepted and spoofed](https://www.rfc-editor.org/info/rfc4795/#section-5.2) by establishing a Machine-in-the-Middle (MitM) position and responding to them with malicious replies, what is known as **LLMNR/NBT-NS poisoning**. This can result in capturing authentication attempts from users (typically NTLMv2 hashes) which can then be cracked offline or [relayed to other services](https://mollysec.com/posts/smb-signing-and-ntlm-relay-explained/).

The below diagram shows how an attacker with an established MitM position can capture a user's credentials:

{{<figure 
    src="/images/llmnr-nbt_ns-poisoning.png"
    alt="The process of name resolution."
    width="950"
    caption=""
>}} 

Now we got the high-level picture, let's see how each protocol works.

# NBT-NS

Let’s start with some terminology so we know what we are talking about:

- **[Network Basic Input/Output System (NetBIOS)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/760f8b7f-9a8a-4f0c-a044-1501a83a933b#gt_b86c44e6-57df-4c48-8163-5e3fa7bdcff4)** is a legacy API that allows applications on different hosts to communicate over a LAN.
- **[NetBIOS over TCP/IP (NBT)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/45170055-a0cd-4910-9228-801d5bf7ac84)**, as the name implies, is a NetBIOS extension that works over IP-based networks.
- **NetBIOS over TCP/IP Name Service (NBT-NS)**, often referred to as **[NetBIOS Name Service (NBNS)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/760f8b7f-9a8a-4f0c-a044-1501a83a933b#gt_a28c2e64-21dd-46ca-9aea-42204fbb8411)**, is responsible for name registration and resolution in legacy Windows environments. It can operate using broadcast-based queries or leverage the **[Windows Internet Name Service (WINS)](https://learn.microsoft.com/en-us/windows-server/networking/technologies/wins/wins-top)**, a centralised name resolution service designed to reduce broadcast traffic by providing a dedicated server for NetBIOS name lookups.

Although NBT-NS is a legacy protocol (introduced in 1983!), it is still widely present in modern environments. By default, Windows machines are configured to `Use NetBIOS setting from the DHCP server` which means that:
- If the DHCP server provides NetBIOS configuration, the client will follow its behaviour. For instance, if DHCP has a hybrid [node type](https://datatracker.ietf.org/doc/html/rfc2132#section-8.7) ([H-node](https://kb.gtkc.net/setting-netbios-node-types-in-dhcpd-conf)), a WINS server will be queried first, followed by broadcast-based resolution.
- If the DHCP server does not provide a NetBIOS configuration or if the system uses a static IP address, NBT-NS will be enabled.

{{<figure 
    src="/images/nbtns-settings.png"
    alt="How to configure the NBT-NS in Windows."
    width="950"
    caption=""
>}}

As a result, if no one bothers to explicitly disable NBT-NS, it will probably be there. We can confirm that this is the case by starting a [Wireshark](https://www.wireshark.org/) capture on the UDP port 137 and then trying to resolve a non-existing path (the `<20>` part on the query represents a [NetBIOS suffix](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbte/6dbf0972-bb15-4f29-afeb-baaae98416ed#:~:text=File%20Server%20Service), in this case a file server or SMB service):

> *Although NBT-NS is seen as broadcast-based name resolution, Windows systems may also issue unicast NetBIOS queries to specific hosts. These are part of the operating system’s resolution heuristics and may target known network devices (e.g. default gateways) as part of parallel resolution attempts.*

{{<figure 
    src="/images/nbt-ns-wireshark.png"
    alt="Capturing NBT-NS traffic with Wireshark."
    width="950"
    caption=""
>}}

# LLMNR

[Link-Local Multicast Name Resolution (LLMNR)](https://www.rfc-editor.org/info/rfc4795/) was introduced around 2006-2007 as the successor of NBT-NS. It serves the same goal with NBT-NS: provide name resolution in scenarios where conventional DNS is not available. 

Similarly with NBT-NS, LLMNR often exists on the domain because no one has bothered to disable it. As shown below, if the `Turn off multicast name resolution` policy setting is not explicitly enabled, then LLMNR will be present:

{{<figure 
    src="/images/llmnr-setting.png"
    alt="The local group policy for LLMNR on Windows."
    width="950"
    caption=""
>}} 

We can confirm that LLMNR traffic is present by starting a [Wireshark](https://www.wireshark.org/) capture on the UDP port 5355:

{{<figure 
    src="/images/llmnr-wireshark.png"
    alt="Capturing LLMNR traffic with Wireshark."
    width="950"
    caption=""
>}}

Although LLMNR uses a predefined multicast group (`224.0.0.252`) rather than broadcast traffic, this does not provide any form of access control. Any host on the local network can join the multicast group, receive queries, and send responses. As a result, multicast improves efficiency (by reducing network traffic), but does not introduce trust.

While there are [articles](https://tcm-sec.com/llmnr-poisoning-and-how-to-prevent-it#:~:text=LLMNR%20has%20no%20authentication%20mechanism) stating that ***LLMNR has no authentication mechanism***, thus, allowing any host on the network to respond to LLMNR requests, this is theoretically wrong (but practically true). As a matter of fact LLMNR has not one, but [three authentication options](https://www.rfc-editor.org/info/rfc4795/#section-5.3):

- [TSIG](https://www.rfc-editor.org/info/rfc2845/) is based on **a group of hosts (e.g. domain-joined systems) sharing a secret key used to sign and verify LLMNR messages**. This can effectively prevent rogue devices on the network from responding to LLMNR queries. However, in case of a compromised domain-joined machine, the key will also be compromised anyway.
- [IPsec](https://www.rfc-editor.org/info/rfc5406/) authenticates hosts rather than messages. It **can prove who sent the response**, but not whether that host is actually authoritative for the name it claims. It can leverage [Kerberos or an existing PKI](https://www.rfc-editor.org/info/rfc5406/#section-3.3) (e.g. ADCS), so it may seem to be a good choice in environments where these are already deployed. However, similarly to TSIG, if a domain-joined machine is compromised, it will already have a valid identity (e.g. cert or TGT). As a result, IPsec provides a similar level of protection to TSIG: it can prevent unauthorised devices from participating in LLMNR, but cannot stop already trusted hosts from impersonating arbitrary names.
- [DNSSEC](https://www.rfc-editor.org/info/rfc4033/) is the last and (in theory) strongest option; it **allows a responder to prove ownership of a name**. However, DNSSEC relies on a hierarchical trust model, which LLMNR lacks. Without delegation, trust anchors, or authoritative servers, there is no mechanism to establish or validate that trust.

If you ever wrote or read a pentest report which included LLMNR Poisoning as a finding, I am almost certain that the mitigation was to **just disable it**. But why is this the case? 

As we already said, DNS can fail for multiple reasons and companies need to not be interrupted, thus, having a fallback mechanism seems like a no-brainer. Since mechanisms like TSIG and IPsec can make it a bit more secure (at least against rogue systems), why not go that way? Well, for a couple of reasons:
- First, the rogue device vector does **not really align with the modern threat model**. In real-world environments, attackers rarely operate from arbitrary, unauthorised devices, but gain a foothold on domain-joined systems through phishing, malware, or other initial access vectors. As discussed, neither TSIG nor IPsec can protect against that.
- Given the **operational complexity of deploying such mechanisms** and the limited security benefit they provide, it is just not worth the hassle. Modern enterprise environments rely on a properly configured DNS rather than opportunistic local resolution, and they prefer to have DNS failures rather than an insecure fallback.

At the end of the day, **LLMNR prioritises convenience over security** and creates an attack surface that can be exploited even in otherwise well-configured environments. As a result, the standard approach is to disable it entirely and eliminate the attack surface altogether rather than attempt to control an inherently insecure protocol.

So both NBT-NS and LLMNR seem to be enabled on almost every domain because no one has explicitly disabled them!

# mDNS

[Multicast DNS (mDNS)](https://www.scoutdns.com/library/mdns-llmnr-and-local-name-resolution/#multicast-dns-mdns) is another name resolution protocol designed to operate without a traditional DNS server (e.g. [a home network](https://wellstsai.com/en/post/mdns-iot-device-discovery/)). Similar to LLMNR, mDNS uses **multicast queries** sent to a predefined group address (`224.0.0.251`).

mDNS is commonly associated with **service discovery protocols** (e.g. Apple’s Bonjour), and is widely used in environments where devices need to dynamically locate each other (e.g. printers, file sharing, or screen casting). In these scenarios, hosts advertise and discover services using names within the `.local` namespace.

{{<figure 
    src="/images/mdns.png"
    alt="A flowchart showing how mDNS works."
    width="950"
    caption="Image taken from [here](https://www.scoutdns.com/library/mdns-llmnr-and-local-name-resolution/)."
>}} 

From a functionality perspective, mDNS behaves pretty much the same as LLMNR: when a host attempts to resolve a name and DNS fails, it may issue a multicast query asking if any host on the LAN can respond. As with the other protocols, the first valid response is typically accepted and it will be enabled if not explicitly disabled.

{{<figure 
    src="/images/mdns-policy.png"
    alt="The default policy of mDNS."
    width="950"
    caption=""
>}}

We can validate this by capturing traffic on the UDP port 5353 and trying to resolve something with the `.local` suffix:

{{<figure 
    src="/images/mdns-wireshark.png"
    alt="The default policy of mDNS."
    width="950"
    caption=""
>}}

In practice, mDNS is less commonly associated with credential capture in Windows environments. Unlike LLMNR and NBT-NS, it is not tightly integrated with authentication flows (e.g. SMB) and is primarily used for service discovery rather than domain resource access. In addition, unlike LLMNR and NBT-NS, mDNS is often required for legitimate functionality (e.g. network printers, AirPlay, or conferencing systems).

# Mitigation

The most effective mitigation for these protocols is to [disable them](https://woshub.com/how-to-disable-netbios-over-tcpip-and-llmnr-using-gpo/) entirely (see more here for disabling [NBT-NS](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-6-%E2%80%93-enforcing-smb-signing/4272168)). In modern environments, properly configured DNS infrastructure is sufficient for name resolution, and maintaining inherently insecure fallback mechanisms is not worth the risk.

If disabling these protocols is not feasible, the impact of potential attacks can be reduced. Enforcing strong and unique passwords across all user accounts limits the effectiveness of credential capture by making offline cracking significantly harder. In addition, enabling protocol-level protections such as [SMB signing](https://mollysec.com/posts/smb-signing-and-ntlm-relay-explained/) as well as [LDAP signing and channel binding](https://mollysec.com/posts/ldap-singing-and-channel-binding-explained/) can mitigate NTLM relay attacks by preventing attackers from forwarding captured authentication to other services.

**Note**: Changes to name resolution behaviour should be carefully tested before being deployed in a production environment. Disabling certain protocols, particularly mDNS, can introduce unexpected operational issues, such as broken printer discovery or loss of screen sharing and casting functionality in conferencing environments!