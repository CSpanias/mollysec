---
title: "Password Audits Part 4: Analysing Results"
date: 2026-07-24
author: "mollysec"
description: "Generating meaningful statistics."
featured: true
tags: ["ntds", "hashcat", "passwords", "analysis", "password-analyser", "ntlm", "lm", "hashes", "active directory"]
categories: []
series: "Password Audits"
thumbnail: ""
draft: true
---

# Introduction

We finally reached the final part of the process! We [extracted NTDS](https://mollysec.com/posts/password-audits-part-1/), then [organised it](https://mollysec.com/posts/password-audits-part-2/), and finally [recovered as many hashes as we could](https://mollysec.com/posts/password-audits-part-3/). Now, it is time to produce some value from all that!

---

~~Extract NTDS~~ → ~~Clean/Organise NTDS~~ → ~~Crack Hashes~~ → **Analyse Results**

---

At this point, we should have a collection of recovered credentials (the hashcat potfile!) and a rough understanding of how successful our password-cracking efforts were. However, simply knowing that a certain percentage of hashes were recovered does not tell the whole story. 

For example, imagine that we recovered 263 passwords from a domain. What does that actually mean? On its own, the number provides little context.

The goal here is to build that context ourselves by analysing the recovered hashes. We want to do that while producing as little noise as possible. For example, I have seen tools generate metrics like the following: 

> The top X characters used were:
>
> |Character|Times Used|Percentage|
> |---|---|---|
> |a|50|65%|
> |o|45|63%|
> ...

Don't get me wrong, I like statistics as the next guy. I have actually done (in purpose) many stats-related courses during my uni years and fiddling with [R](https://www.r-project.org/about.html) for my [MSc's thesis](https://www.researchgate.net/publication/366435891_Position_before_submission_Techniques_and_tactics_in_competitive_no-gi_Brazilian_jiu-jitsu) was what motivated me to switch careers in the first place!

But let's be honest for a second. What value is really gained from knowing that the latter `a` appears more frequently than the latter `o`? Who really cares and how this kind of statistic ends up is this within an actual report?

The aim here is to think what questions we should be asking, make sure that answering them provides value and can lead to an actual remediation plan. In layman's terms, we want to move from:

> *We cracked 13.6% of the domain passwords.*

to:

> *Several privileged accounts were compromised, multiple users were found to share passwords, and a significant proportion of recovered credentials contained predictable patterns that could facilitate targeted password attacks.*

The first statement is a statistic, whereas the second starts to resemble an actual finding.

To stay consistent with the trend of our era, we will finish by vibe-coding a small Proof-of-Concept (PoC) tool to automate the whole process.

# Enumerating the Right Questions

So we have cracked an NTDS dataset and recovered some hashes which is cool by itself. **What are the major risks that are hidden within this dataset?** Some questions that might help answering this questions are:

1. How many hashes were recovered?
2. Were any privileged accounts recovered?
3. Are any recovered passwords non-compliant with the domain password policy?
4. Are any passwords being reused across multiple accounts?
5. Are similarly named accounts sharing passwords?
6. Do recovered passwords exhibit common weak patterns?

Let's see how each question could potentially help us towards a more secure domain.

The **percentage of recovered hashes** can serve as a first indication before we even start our analysis. Imagine we cracked 6% versus 60% of NTDS; the latter is likely to indicate one or more underlying weaknesses within the organisation's password practices. Most probably a really weak domain password policy or a culture of password reuse within the organization. This is a good starting point.

Now the second question is a bit more tricky, because **the definition of "privileged" is open to interpretation**. Most people here would include just the obvious choices, such as Enterprise Admins (EAs) and Domain Admins (DAs). This makes sense; compromising such an account results in compromising the domain itself and most probably the whole forest. However, are these groups the only ones that represent a serious threat for a domain?

What about Account Operators, Backup Operators, Cert Publishers, and DNS Admins, among many others? Getting your hands in a member of those groups can pretty much also result in a full domain compromise. One way or another, if the dataset includes privileged accounts, this should be at the very top of the report!

Now, **non-compliant accounts** can exist for various reasons. They can be the result of legacy accounts (i.e. accounts created prior to the current policy), accounts configured with [Password Not Required](https://specopssoft.com/blog/find-ad-accounts-using-password-not-required-blank-password/), or the result of [Fine-Grained Password Policies (FGPP)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc770394(v=ws.10)). No matter what the cause is, these should be reviewed by the business and decice if there is a legit reason that they violate the domain policy or not.

Then, there is **password reuse**. For example, there might users "forced" to use different accounts for different tasks, e.g. `mike` and `mike_admin`. Althought this is [best practice](https://www.decryptiondigest.com/blog/active-directory-tiering-model#:~:text=Dedicated%20admin%20accounts), it can also create a false sense of security if Mr.Mike uses the same password for both accounts as compromise of the lower-privileged account will provide an attacker with immediate access to the higher-privileged account!

Finally, identifying **recurring patterns** is where password analysis becomes particularly useful. Whilst a single weak password may not reveal much on its own, hundreds of recovered passwords can reveal common user behaviours and password construction habits. We can identify usernames within passwords (e.g. `mikePassw0rd`), date-related strings (e.g. `Monday2026`), commonly used dictionary words (e.g. `Welcome123!`), organisation-related strings (e.g. `MyCompany123!`), keyboard walks (e.g. `qwerty`), and the list goes on!

| Vulnerability                           | Example Remediation                                    |
| --------------------------------------- | ------------------------------------------------------ |
| Large Percentage of Passwords Recovered | Review password policy                                 |
| Privileged Accounts                     | Dedicated password policy and MFA                      |
| Non-Compliant Passwords                 | Review legacy accounts and policy exceptions           |
| Password Reuse                          | Unique passwords and password filtering                |
| Predictable Password Patterns           | User education and banned-password lists               |

Nothing of the above is really complex and all of the answers provide a direction and an actionable step for improving the domain's security. The challenge, therefore, is not generating statistics but identifying which statistics are useful.

With that in mind, let's start building a process capable of extracting these findings from a recovered password dataset.


# Automating the Process with Password-Analyser

Identifying useful questions is only half of the process. The next challenge is answering them consistently across multiple assessments in an easy-to-digest format.

For a small dataset, many of the findings discussed above could be identified manually. However, as the number of recovered credentials increases, the process quickly becomes time-consuming and repetitive. In addition, performing the analysis manually increases the likelihood of inconsistencies between assessments.

For example, determining whether a password contains a username, organisation-related terminology, keyboard patterns, common dictionary words, or other predictable elements is relatively straightforward when reviewing a single password. Performing the same checks across hundreds of recovered credentials is considerably less practical.

While there are some tools out there for this exact job, such as [Pwdlyser](https://github.com/ins1gn1a/Pwdlyser) and [Password Auditor](https://specopssoft.com/product/specops-password-auditor/), either they are deprecated or they can't be customised to one's needs.

So, as always, the goal here is not to do anything fancy, but a small quality of life improvement. To support this process, I created a small PoC named `password-analyser`. The tool takes a list of recovered credentials along with supporting data collected during the previous stages of the workflow and produces statistics, evidence tables, and "report-ready" commentary.

Here I should make a note regarding the data that the tool needs as input.

On [part 2](https://mollysec.com/posts/password-audits-part-2/) of this series, I introduced another very simple PoC called [`hash-organiser`](https://github.com/CSpanias/pass-audit-tools/tree/main/hash-organiser). Since then, I actually created its big brother, [`ntds-organiser`](https://github.com/CSpanias/ntds-organiser), which does kind of the same job but much better.

The `ntds-organiser` script generates (almost) everything we need for the `password-analyser` using the NTDS and Hashcat potfile. The workflow looks like this:
1. Pull NTDS with `secretsdump.py` &rarr; get the `.ntds` file
2. Parse NTDS with `ntds-organiser` to generate the required files &rarr; including `ntlm-hashes.txt`
3. Crack hashes with `hashcat` &rarr; get the `.potfile`
4. Map recovered hashes back to their users with `ntds-organiser` &rarr; get `mapped-passwords.txt` 
5. Analyse the final dataset `password-analyser` &rarr; Done!

For the curious one, those are the files that `ntds-organiser` generates:

{{<figure 
    src="/images/ntds_organiser-files.png"
    alt="The files generated from ntds-organiser tool."
    width="600"
    caption=""
>}}

# Conclusion