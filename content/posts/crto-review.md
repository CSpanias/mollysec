---
title: "My Take on CRTO"
date: "2026-07-19"
author: "mollysec"
description: "My experience taking the Certified Red Team Operator certification."
featured: true
tags: ["zero point security","crto", "rto", "certified red team operator", "red team ops", "cobalt strike", "cobalt", "c2"]
categories: ["review"]
series: ""
draft: false
---

# Introduction

The [Red Team Ops (RTO)](https://www.zeropointsecurity.co.uk/course/red-team-ops) certification has been around for a while and is often recommended as **one of the best entry points into red teaming**. After completing both the course and, in particular, the exam, I can see why.

I had RTO bookmarked for more than a year, but I continuously postponed pulling the trigger. I am a pentester rather than a red teamer, and I don't plan on switching just yet, so I gave priority to certifications that felt more relevant to my day-to-day work, such as [OSCP](https://www.offsec.com/courses/pen-200/) and [CAPE](https://academy.hackthebox.com/preview/certifications/htb-certified-active-directory-pentesting-expert).

After changing jobs and then diving into CAPE a few months later, I quickly hit the **information overload** stage. I was learning a ton of new stuff from both work and CAPE, far more than I could effectively retain.

{{<figure 
    src="/images/info-overload-simpsons.jpg"
    alt="A Simpons meme related to information overload."
    width="550"
    caption=""
>}}

I ended up grinding through the CAPE exam and achieved a passing score within three days. After that, I decided that my next goal should be something more relaxed and as disconnected from my day-to-day work as possible, while still remaining useful.

As you have probably guessed by now, that turned out to be RTO.

# Exam

RTO's exam was recently reworked from a flag-based CTF-style format to a **score-based assessment**. It now requires you to complete an objective in an OPSEC-friendly way.

The objective itself is worth 50 points, while the remaining 50 points come from maintaining good OPSEC. Every detection event, such as a payload being caught by Defender or AppLocker, results in a five-point deduction from the OPSEC score. This means that you **can only afford three mistakes**. A passing score requires 85 points, so on the fourth, you are out!

{{<figure 
    src="/images/crto-review-applocker.png"
    alt="A Windows Defender notification."
    width="650"
    caption=""
>}}

While this may sound scary, it really isn't. The main reason is that **the exam follows the course content really (and I mean really) closely**. It actually reminded me quite a lot of [CRTP](https://www.alteredsecurity.com/post/certified-red-team-professional-crtp) in that regard. Therefore, if you feel comfortable with the techniques covered in the course, there should be very few surprises waiting for you in the exam.

That said, I think CRTP and RTO sit at one end of the spectrum, while [OffSec](https://www.offsec.com/)'s "try harder" approach sits at the other. Both CRTP and RTO follow the course a bit too much (for my taste at least!), whereas OffSec exams feel completely disconnected from the course. Don't get me wrong, I would choose Altered Security's and Zero Point Security's approach over OffSec's any day of the week.

However, if I had to pick the certification that strikes the best balance between course and exam, it would probably be CAPE. It follows the concepts taught during the course, but in a broader way that really challenges your understanding of them. You have to really squeeze your brain to get the pieces together and progress through the exam.

# Unlimited Attempts

One aspect of the RTO that I think is often overlooked is the new exam structure's inclusion of **unlimited re-sits**.

Officially, there is a seven-day cooldown period between attempts. In practice, however, the timer starts when you activate the exam lab. Since the lab provides 24 hours of access that can be used across a seven-day period, you will often be able to attempt a re-sit much sooner. For example, if you exhaust your 24 hours over four days, you could theoretically start another attempt just three days later.

While free re-sits within such a short timeframe are a cool feature by themselves, I think there is a much more practical benefit, and it is probably my favourite aspect of the entire certification.

Most certifications come with a single exam attempt, and additional re-sits are, more often than not, quite expensive. This creates an awkward dynamic between the student and the course. Candidates become **overly focused on passing the exam rather than actually learning the material**. That is why so many preparation guides, "OSCP-like" paths and labs, and even paid "bootcamps" exist.

Students become so fixated on achieving a first-attempt pass that they are willing to pay for expensive bootcamps to prepare them for an expensive course which then prepares them for the actual exam!

{{<figure 
    src="/images/crto-review-cert-bootcamps.png"
    alt="The score of the two exam attempts."
    width="950"
    caption=""
>}} 

**Unlimited attempts fundamentally change that relationship**. Instead of worrying about protecting a finite number of exam vouchers, students can focus on what actually matters. They can experiment, make mistakes, learn from them, and ultimately approach the exam with a far healthier mindset. The certification stops feeling like a high-stakes gamble and starts feeling like what it should be: **a learning experience**.

There is no fear of failure. If things go south, you can review your mistakes, dig into the whys, and try again a few days later without reaching for your wallet. This creates a much healthier learning environment and better aligns the certification process with its real purpose: **helping people develop useful skills rather than simply collecting another badge**.

# Some Tips

**RTO's (main) goal is to teach you how Cobalt Strike works and not how Active Directory (AD) works**. 

By the time I started the course, I already had a good grasp of AD concepts and attack paths through both my day-to-day work and certs like CRTP and CAPE. Thus, my goal was to see how the attacks I already knew could be executed more stealthily using Cobalt Strike.

I mention this because I have seen quite a few people struggle with RTO due to their lack of AD knowledge rather than the red teaming aspects of the course itself. While the course does a good job of explaining the purpose and mechanics of each technique, I think I would have found it significantly harder to follow without a solid AD foundation.

So if your plan is to learn both AD and red teaming at the same time through RTO, I would encourage you to adjust your expectations. However, course access is provided for life, which means there is no rush. If you are happy taking things slowly and filling in the gaps as you go, then by all means ignore my advice and jump in.

**Take advantage of the unlimited re-sit model**.

I marginally failed my first attempt and passed the second with a perfect score. The funny thing is that I probably learned more from the failed attempt than from either the course's labs or the subsequent successful attempt.

{{<figure 
    src="/images/crto-review-scores.png"
    alt="The score of the two exam attempts."
    width="950"
    caption=""
>}} 

Several concepts, like artifact and resource kits, had not fully clicked during the course. They kind of made sense, but not 100%. During my first attempt, I took it as slow as possible and every time a payload got flagged, I noted it down, and made sure to understand why.

**I did not care about passing on the first attempt.**

I treated the first attempt as an extension of the learning process. I experimented, played with different approaches, and focused on understanding the environment. I still completed the objective (18 hours later, that is!), but by the end of the assessment I knew exactly where my four OPSEC mistakes had come from and how to fix them.

That, in my opinion, is where the unlimited re-sit model really shines. **It gives you the freedom to prioritise learning over passing, which ultimately makes passing much easier**. I achieved a perfect score on my second attempt in under two hours!

# Final Thoughts

RTO is what it says it is: **an introductory course to red teaming with Cobalt Strike**.

Completing the course won't magically turn you into a red teamer; it will simply teach you how to use Cobalt Strike and introduce you to some of the workflows commonly used during red team operations.

If your goal is to ease your way into red teaming in a casual, low-stress, and, therefore, genuinely enjoyable manner, I don't think there is currently a better certification to do it with!