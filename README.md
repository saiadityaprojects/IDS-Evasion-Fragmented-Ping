# IDS Evasion Using Fragmented Ping

> Bypassed Snort 2.9.20 IDS using IP-fragmented ICMP packets via hping3 — zero alerts triggered on a custom `dsize:>7` detection rule. Full methodology, Snort rule, and timestamped evasion proof included.

![Status](https://img.shields.io/badge/Status-Completed-brightgreen)
![IDS](https://img.shields.io/badge/IDS-Snort%202.9.20-blue)
![Tool](https://img.shields.io/badge/Evasion%20Tool-hping3-red)
![Lab](https://img.shields.io/badge/Environment-Isolated%20VMware%20Lab-lightgrey)

---

## Overview

This project demonstrates a complete end-to-end IDS evasion technique performed in an isolated virtual lab environment as part of the **Anonymous India Ethical Hacking Internship (March 2026)**.

The goal was to:
1. Deploy and configure **Snort 2.9.20** as a live IDS on Ubuntu 24.04
2. Write a custom ICMP detection rule and confirm it detects normal ping traffic
3. Use **hping3** with IP fragmentation to send packets that fall below the rule's detection threshold — achieving **zero alerts** while maintaining full connectivity

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Attacker | Kali Linux — `192.168.109.129` |
| Defender / IDS | Ubuntu 24.04.4 LTS — `192.168.109.132` |
| IDS Software | Snort 2.9.20 GRE (Build 82) |
| Evasion Tool | hping3 |
| Network | VMware VMnet8 (NAT) — isolated, no external traffic |

---

## The Technique

Standard `ping` sends a **56-byte ICMP payload**. The Snort rule was configured to alert only when payload size exceeds 7 bytes (`dsize:>7`). By using hping3 with a **1-byte payload** (`-d 1`) and **forced IP fragmentation** (`-f`), the packets slip below the threshold — the rule never fires.

```
Normal ping   →  56-byte payload  →  dsize:>7 = TRUE   →  ALERT fired
hping3 -d 1   →   1-byte payload  →  dsize:>7 = FALSE  →  NO alert
```

The `frag3` defragmentation preprocessor in Snort was also disabled in `snort.conf`, preventing Snort from reassembling fragments before rule inspection — eliminating the last line of defence against this technique.

---

## Snort Rule

Written in `/etc/snort/rules/local.rules`:

```snort
# Rule v1 — catches all ICMP (baseline test only)
#alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)

# Rule v2 — refined with payload threshold (exploitable)
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; itype:8; dsize:>7; sid:1000001; rev:2;)
```

| Component | Value | Purpose |
|-----------|-------|---------|
| `itype:8` | ICMP Type 8 | Match echo requests only |
| `dsize:>7` | Payload > 7 bytes | **The exploitable threshold** |
| `sid:1000001` | Custom ID | Local rules range (>1,000,000) |

---

## Evasion Command

```bash
# Fragmented ICMP with 1-byte payload — timestamped for proof
date && sudo hping3 -1 -f -d 1 -c 5 192.168.109.132 && date
```

| Flag | Meaning |
|------|---------|
| `-1` | ICMP ping mode |
| `-f` | Force IP fragmentation at the IP layer |
| `-d 1` | 1-byte data payload — **below the dsize:>7 threshold** |
| `-c 5` | Send 5 packets |

---

## Result

| | Normal `ping` | hping3 Fragmented |
|--|--------------|-------------------|
| Payload | 56 bytes | 1 byte |
| IP Fragmentation | No | Yes |
| Snort Alert? | ✅ YES — 5 alerts | ❌ ZERO alerts |
| Connectivity | 0% packet loss | 0% packet loss |
| **Verdict** | **Detected** | **Evaded** |

Timestamped evidence confirmed **zero SID:1000001 alerts** during the entire hping3 execution window (02:43:33–02:43:37 IST), while the same Snort instance was actively detecting normal pings in the minutes before.

---

## Phases

| Phase | Action | Status |
|-------|--------|--------|
| 1 | Ubuntu 24.04 installed, SSH enabled, network verified | ✅ |
| 2 | Snort 2.9.20 installed, HOME_NET configured, ens33 detected | ✅ |
| 3 | Custom ICMP rule written (`itype:8`, `dsize:>7`, SID:1000001) | ✅ |
| 4 | Normal ping triggered SID:1000001 on every packet — baseline confirmed | ✅ |
| 5 | hping3 `-1 -f -d 1` sent 5 packets — zero Snort alerts — evasion proven | ✅ |

---

## Defensive Recommendations

These are the fixes that would have prevented this evasion:

```snort
-- 1. Remove dsize restriction entirely
alert icmp any any -> $HOME_NET any (msg:"ICMP Echo"; itype:8; sid:1000001; rev:3;)

-- 2. Explicitly catch tiny payloads
alert icmp any any -> $HOME_NET any (msg:"Tiny ICMP Probe"; itype:8; dsize:<8; sid:1000003; rev:1;)

-- 3. Detect fragmented packets directly
alert ip any any -> $HOME_NET any (msg:"Fragmented IP Detected"; fragbits:M; sid:1000002; rev:1;)
```

- Keep `frag3` preprocessor **enabled** in production — never comment it out
- Deploy Snort in **inline IPS mode** rather than passive IDS mode to block, not just alert
- Regularly audit custom rules for over-restrictive conditions that create detection gaps

---

## Files in This Repo

```
IDS-Evasion-Fragmented-Ping/
├── README.md
├── report/
│   └── Assessment_11C_IDS_Evasion.pdf
├── snort-rules/
│   └── local.rules
└── screenshots/
    ├── figure_08_snort_baseline_detection.png
    └── figure_10_evasion_confirmed_zero_alerts.png
```

---

## Disclaimer

> This project was conducted exclusively in an **isolated VMware lab environment** with no connection to external networks or real systems. All techniques were performed on intentionally vulnerable virtual machines for educational purposes as part of a supervised ethical hacking internship. This work is intended to demonstrate defensive awareness — understanding how evasion works is essential to building better detection.

---

*Sai Aditya — Ethical Hacking Intern, Anonymous India — March 2026*
