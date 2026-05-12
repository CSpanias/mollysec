---
title: "Password Audits Part 3: Hash Analysis"
date: 2026-03-15
author: "mollysec"
description: "Article focusing the process of recovering hashes extracted from the NTDS.dit file (Active Directory's database), during the password audit process."
featured: true
tags: [
]
categories: [

]
series: "Password Audits"
thumbnail: "/images/password-audits-part-3-thumbnail.jpg"
draft: true
---

# Introduction


# Cracked Hashes Analysis

- Statistical analysis tools
- a custom version of `pwdlyzer` (6 years old)
- a bit finicky, but outputs what we need for the custom reporting platform
- that is XLM files mapped to the platforms findings and stock text for each section of the finding
- Is there any other modern tool we can use for that?
- I currently used `-D 2 -O` to use both GPUs and optimised kernels. Is this the best optimisation?

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