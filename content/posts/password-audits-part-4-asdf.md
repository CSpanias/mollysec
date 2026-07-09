---
title: "Password Audits Part 4: Analysing Results"
date: 2026-06-26
author: "mollysec"
description: "Generating meaningful statistics."
featured: true
tags: ["ntds", "hashcat", "passwords", "dcsync", "drsuapi", "ntlm", "lm", "hashes"]
categories: []
series: "Password Audits"
thumbnail: ""
draft: true
---

# Introduction


# Cracked Hashes Analysis

- Statistical analysis tools
- a custom version of `pwdlyzer` (6 years old)
- a bit finicky, but outputs what we need for the custom reporting platform
- that is XLM files mapped to the platforms findings and stock text for each section of the finding
- Is there any other modern tool we can use for that?

- [Specops Password Auditor](https://specopssoft.com/product/specops-password-auditor/)
- [Pwdlyser](https://github.com/ins1gn1a/Pwdlyser)
- [WPT](https://www.knowbe4.com/free-cybersecurity-tools/weak-password-test)

# Reporting

- We report common stats, such as DA passwords, pass reuse, common words, etc.
- Add % cracked per hashcat run to demonstrate pass strength?
- Benchmarks against standards?
    - Verizon's Data Breach Investigations Report
    - SocinumSecure's credential review reports
    - Meta-analyses
- can KnowBe4's WPT tool be of any use?
- is worth “comparing” to popular frameworks such as NIST, NCSC, etc?
- Report generation and findings presentation
- Recommendations and remediation guidance