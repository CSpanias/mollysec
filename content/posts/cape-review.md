---
title: "My Take on CAPE"
date: "2026-05-12"
author: "mollysec"
description: "My experience taking Hack the Box's Certified Active Directory Pentesting Expert Exam."
featured: true
tags: ["hack the box","htb","certified active directory pentesting expert","cape"]
categories: ["review"]
series: ""
draft: false
---

# Introduction

Although there are a few CAPE-related articles and videos out there, some can make the exam look scarier and more complicated than it actually is; they certainly had that effect for me!

For instance, my biggest concern after reading them was evasion, as this is one of my weakest areas. In addition to that, I am working from a laptop with fairly limited resources, and let's just say that installing Visual Studio and compiling stuff on it is not ideal. 

So reading that I need to have a ready-to-compile environment or write custom payloads to pass the exam was a bit worrying.

With that in mind, I will start by briefly addressing a few general aspects of the exam that are good to have sorted out before diving into the actual lab "details".

## Reporting

As far as reporting goes, I used [SysReport](https://docs.sysreptor.com/setup/installation/) along with the [CAPE template](https://github.com/Syslifters/HackTheBox-Reporting) and my report ended up to be ~100 pages. While this might sound like a lot, it is really not. 

If you are writing reports in your day-to-day job, the process should be relatively straightforward; if you don't, it might take you some more time.

If you have never used SysReport before, maybe it is worth familiarising yourself with it beforehand to avoid any surprises when it's time to use it.

## Double Pivoting

Another thing that is good to be confident with is double pivoting. It might seem complicated at first, but even if you never had to do it before, [`ligolo-ng`](https://github.com/nicocha30/ligolo-ng) makes this process trivial. Just watch r1ckyr3c0n's [video](https://www.youtube.com/watch?v=de7IP_uZK6E), practice it yourself a few times, and you will be golden.

One thing that might be worth highlighting here is that the SSH host has some outdated tools under `/opt`, including `ligolo-ng`. I had prepared my own toolset to use, including the latest version of `ligolo-ng`, but when I did, the tunnel kept dropping every few minutes. After wasting half a day, I switched to the outdated version of the SSH host, and the tunnel never dropped once.

I haven't seen anyone else talking about this, so it might be that the environment had some issues unrelated to `ligolo-ng` that just happened to resolved when I switched to the outdated version. I will never know!

## Evasion

As I already mentioned, some CAPE-related articles can give the impression that evasion is a big part of the exam. I have to admit, I am all about AD, but not at all about red teaming; at least not for now. 

Based on the course content (only 1/15 modules touched on evasion), I found the idea of evasion being an important part of an AD-pentesting-focused exam bizarre.

I am not saying there is anything wrong with having a VM compiling custom exploits and bypassing Defender like it is not even there. What I am saying is that I was not in the mood for that, and that my goal was to do the bare minimum on that front.

My idea of evasion before sitting for CAPE was the following:
- If an out-of-box binary was blocked by Defender (e.g. `winPEASany.exe`), I would just use its obfuscated version (e.g. `winPEASany_ofs.exe`).
- If I needed a reverse shell and none of my go-to [revshells.com](https://www.revshells.com/) payloads work, I would opt for an obfsucated Sliver beacon (ugh!).

It was not always straightforward, but it was not so hard either. Believe me when I say, since I managed to work through the evasion part, you certainly can too!

## Context

For context, prior to CAPE, I had close to zero professional AD-related experience and somewhat average lab experience. More specifically:
- I have done my fair share of Windows/AD-related boxes as well as a few [prolabs](https://www.hackthebox.com/hacker/pro-labs#prolabs-scroll) (P.O.O., Dante, and Zephyr). All that about a year ago.
- I have studied the [CPTS](https://academy.hackthebox.com/preview/certifications/htb-certified-penetration-testing-specialist) path (~2 years ago) and have also taken some relevant to CAPE certs, such as [CRTP](https://www.alteredsecurity.com/post/certified-red-team-professional-crtp) and [OSCP](https://www.offsec.com/courses/pen-200/).
- Although I have been working as a pentester for ~2.5 years, the first two were almost exclusively on web apps/APIs. I actually did my first internal just a few months ago (yay!).

With all that out of the way, here's how the exam looked from my perspective.

# What to Expect

## Setup

To begin with, for some reason, I was certain that CAPE was an assumed breach scenario, i.e., that you start with a valid domain account and go from there. That's not the case.

You are given creds for a non-domain user that can SSH into a host that can communicate the target network. The initial setup looks like this:

{{<figure 
    src="/images/cape-setup.png"
    alt="The initial setup when starting the CAPE exam."
    width="auto"
    caption=""
>}} 

Then it's up to you how you go from there. 

## Enumeration

As others have already said (see [here](https://lorenzomeacci.com/htb-cape-review#tips-for-the-exam) and [here](https://thepastamentor.github.io/cape-prep-guide.html#essential-tooling)), enumeration is the name of the game. 

What I found most interesting about the lab, is that although almost every attack vector is taught during the course (yes, CAPE should be "enough" to pass the exam), the attack itself is never straightforward. The environment is designed in such a way that tries its best to really test your understanding of each attack.

If you expect to gather domain data and let BloodHound lay out the attack path for you, you will be disappointed. The lab requires to level up your enumeration and be able to sniff out an attack vector by seeing scattered pieces here and there. It looks something like this:

1. Enumerate and collect data
2. Form a hypothesis about a potential attack path
3. Attempt to validate it
4. If it works, move forward (or more like backward to Step 1!)
5. If not, understand why it failed and adjust accordingly

I found the last point to be particularly important. If something fails, treat it as feedback rather than a setback. Don't rush to switch techniques; you might be missing a prerequisite or you have made a wrong assumption for something that can be replaced with something else.

On various occasions, I had an idea of what the attack vector might be, and I found myself asking:

- What condition must be true for this attack to work?
- What specific element(s) am I missing and how can I best enumerate for it?

Answering these questions almost always led me to the next step.

# Practice

After completing the path, I had about one month until the exam. My initial plan was to tackle the Cybernetics pro lab. Due to environment issues, I was spending more time troubleshooting and waiting for hosts to come back alive rather than practicing, so I had to let that idea go real quick. As an alternative, I started working on individual AD boxes instead.

Below is a list of retired boxes that I believe to be a good practice to get you in the required mindset. I should note, that these boxes are not relevant in a sense that they have the same attack vectors with the actual exam, but rather that they force you to think in a similar way and practice core AD concepts.

My approach when tackling boxes is to first let myself "grind" for a bit. If I am confident that I have tried everything I know and still can't get through it, then I opt for a walkthrough, either from [0xdf](https://0xdf.gitlab.io/) or [IppSec](https://www.youtube.com/@ippsec). For context, I needed hints to solve most of these boxes and still did OK in CAPE, so treat them as a way to learn new things, don't try to reinvent the wheel.

As you probably already know, CAPE lists CPTS as a prerequisite, so I take stuff like host/share (SMB, FTP, NFS) enumeration, password spray, brute force attacks (BFA), etc. as granted. The BFA tag on the table means that "smart" (i.e., simple and sensical) custom wordlists are used. I have also intentionally skipped some boxes due to their reliance on web stuff as it is out of scope for CAPE. Finally, on the Relevancy column, I just highlight what AD concepts each box helps you practice; obviously, each box includes a lot more that just those.

The below boxes are good for "warm up", i.e., you should feel pretty comfortable solving them without needing much help. If you feel that you are struggling, I would recommend spending some time to understand why.

| Box | Rating | Relevancy |
| --- | ------ | --------- |
| [EscapeTwo](https://www.hackthebox.com/machines/escapetwo) | Easy | ACL-Based Enum, ADCS |
| [Retro](https://www.hackthebox.com/machines/retro) | Easy | BFA, Pre2k |
| [ShadowGate](https://www.hacksmarter.org/courses/e7586073-d447-41db-8f8e-6bd22576556d) | Easy | AS-REP Roasting, ACL-based Enum, ADCS |
| [MartiniAD]() | Easy | Kerberos, Kerberoasting, Password Spray |
| [Certified](https://www.hackthebox.com/machines/Certified) | Medium | ACL-Based Enum, ADCS |
| [Delegate](https://www.hackthebox.com/machines/delegate) | Medium | ACL-Based Enum, Unconstrained Delegation |
| [Escape](https://www.hackthebox.com/machines/Escape) | Medium | MSSQL, ADCS |
| [Phantom](https://www.hackthebox.com/machines/Phantom) | Medium | Password Spray, RBCD |
| [Redelegate](https://www.hackthebox.com/machines/Redelegate) | Hard | BFA, ACL-Based Enum, Constrained Delegation |

The next list of boxes isn't too hard either, but they can be a challenge if your notes are missing a few things:

| Box | Rating | Relevancy |
| --- | ------ | --------- |
| [Baby](https://www.hackthebox.com/machines/baby) | Easy | LDAP Enumeration |
| [Voleur](https://www.hackthebox.com/machines/VOLEUR) | Medium | Kerberos, DPAPI, Deleted Objects |
| [Breach](https://www.hackthebox.com/machines/Breach) | Medium | SMB Uploads, MSSQL |
| [Sendai](https://www.hackthebox.com/machines/Sendai) | Medium | ACL-Based Enum, Troubleshooting Auth Erros, ADCS |
| [BabyTwo](https://www.hackthebox.com/machines/babytwo) | Medium | Logon Scripts, ACL-Based Enum, GPO Abuse |
| [TombWatcher](https://www.hackthebox.com/machines/tombwatcher) | Medium | ACL-Based Enum, Deleted Objects, ADCS |
| [VulnCicada](https://www.hackthebox.com/machines/VulnCicada) | Medium | Kerberos, ADCS |
| [Signed](https://www.hackthebox.com/machines/Signed) | Medium | MSSQL, NTLM Reflection |
| [DarkZero](https://www.hackthebox.com/machines/DarkZero) | Hard | MSSQL, Logon Types, Forest Trusts |
| [RustyKey](https://www.hackthebox.com/machines/RustyKey) | Hard | Kerberos, Timeroasting, RBCD |

What I would highly recommend is that even if BloodHound lays down a path for you (e.g. `poppy` has `WriteOwner` over `henry`), try to then take a step back and go about enumerating that "manually" as if you did not have BloodHound available (e.g. using `dacledit.py` or any other similar tool). Ask yourself:
- How would I go about checking what permissions each object might have on all other domain objects with just a userlist at hand?
- How do I enumerate the specific element that I am missing for what I think is the potential attack vector for moving forward?

# Final Thoughts

The bottom line is that CAPE wants you to succeed and is not designed to trick you in any way. Although, I found some elements that I ended up not using at all, I can't say that the exam had any major rabbit hole.

If you approach the exam as a collection of predefined attacks which can be executed by simply copying and pasting commands from the course as they are, it will probably feel overwhelming. If you approach it as a system that you need to gradually understand and map out, you will probably do well and have fun in the process!