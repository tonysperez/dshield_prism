# 5452a0bcfeaf

- **Source IP:** `213.144.214.231` — France — AS15557 Societe Francaise Du Radiotelephone - SFR SA
- **SSH client banner:** `SSH-2.0-OpenSSH`
- **HASSH:** `88e4f54f942892da498676735732aec7`
- **Window:** `2026-05-10T05:44:13.160000+00:00` → `2026-05-10T05:44:14.145000+00:00`  (~1.0s)

## Rollup

- **commands:** 1 total (1 unique) · entropy -0.00
- **novelty_score:** mean 0.096 · max 0.096  *(corpus-relative; limited use disconnected from source corpus)*
- **intel:** *(no source_ip_intel block on rollup)*

## Login attempts

1 successful · 0 failed

| outcome | user | password |
|---|---|---|
| success | `test` | `Abc123` |

## Command stream

| # | offset | action | command_line |
|---:|---|---|---|
| 1 | `+00:00.85` | `input` | `cat /proc/cpuinfo\|grep name\|cut -f2 -d':'\|uniq -c ; uname -a` |
| 2 | `+00:00.85` | `failed` | `cat /proc/cpuinfo \| grep name \| cut -f2 -d: \| uniq -c` |

## Artifacts (1)

| kind | value |
|---|---|
| `file` | `/proc/cpuinfo` |
