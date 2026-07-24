"""Fail-closed, owned iptables policy generations for Waygate."""

from __future__ import annotations

import json
import shlex
import re
from uuid import UUID
import subprocess
from ipaddress import IPv4Network
from typing import Callable, Iterable, Sequence

from .domain import ClientForwardPolicy


class NetworkUnavailable(RuntimeError):
    pass


_BLOCKED = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")


class LinuxNetworkControl:
    """Changes only WAYGATE-owned chains. A live generation is never flushed."""

    def __init__(self, run: Callable[[list[str]], subprocess.CompletedProcess[bytes]] | None = None) -> None:
        self._execute = run

    def _run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        argv = ["iptables", "-w", "5", *args]
        try:
            result = self._execute(argv) if self._execute else subprocess.run(argv, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            raise NetworkUnavailable("iptables reconciliation failed") from exc
        if check and result.returncode:
            raise NetworkUnavailable("iptables reconciliation failed")
        return result

    def _exists(self, table: str, chain: str) -> bool:
        return self._run("-t", table, "-S", chain, check=False).returncode == 0

    def _ensure_chain(self, table: str, chain: str) -> None:
        if not self._exists(table, chain):
            self._run("-t", table, "-N", chain)

    def _ensure_jump(self, table: str, parent: str, chain: str, *, first: bool) -> None:
        if self._run("-t", table, "-C", parent, "-j", chain, check=False).returncode:
            if first:
                self._run("-t", table, "-I", parent, "1", "-j", chain)
            else:
                self._run("-t", table, "-A", parent, "-j", chain)

    def _verify_stage_jump(self, parent: str, chain: str) -> None:
        lines = self._run("-S", parent).stdout.decode("utf-8", "replace").splitlines()
        rules = [line for line in lines if line.startswith(f"-A {parent} ")]
        expected = f"-A {parent} -j {chain}"
        matches = [line for line in rules if line == expected]
        if len(matches) != 1 or not rules or rules[0] != expected:
            raise NetworkUnavailable("stage-chain ordering drift")

    def _verify_stage_rule(self, chain: str, rule: tuple[str, ...], *, present: bool) -> None:
        rendered = "-A " + chain + " " + " ".join(rule)
        lines = self._run("-S", chain).stdout.decode("utf-8", "replace").splitlines()
        count = sum(line == rendered for line in lines)
        if (present and count != 1) or (not present and count != 0):
            raise NetworkUnavailable("stage rule readback mismatch")

    def _install_boot_guards(self, interface: str, vpn: IPv4Network, api_port: int) -> None:
        guards = (("WAYGATE_BOOT_INPUT", (("-i", interface, "-s", str(vpn), "-j", "REJECT"), ("-p", "tcp", "--dport", str(api_port), "-j", "REJECT"), ("-j", "RETURN"))), ("WAYGATE_BOOT_FWD", (("-i", interface, "-s", str(vpn), "-j", "REJECT"), ("-o", interface, "-d", str(vpn), "-j", "DROP"), ("-j", "RETURN"))))
        for chain, rules in guards:
            self._ensure_chain("filter", chain)
            existing = [line for line in self._run("-S", chain).stdout.decode("utf-8", "replace").splitlines() if line.startswith(f"-A {chain} ")]
            expected = [self._rule_key(chain, rule) for rule in rules]
            actual = [self._rule_key(chain, line) for line in existing]
            if existing and actual != expected:
                raise NetworkUnavailable("boot guard drift")
            if not existing:
                for rule in rules:
                    self._run("-A", chain, *rule)
        for parent, stage, chain in (("INPUT", "WAYGATE_STAGE_IN", "WAYGATE_BOOT_INPUT"), ("FORWARD", "WAYGATE_STAGE_FWD", "WAYGATE_BOOT_FWD")):
            if self._run("-C", parent, "-j", chain, check=False).returncode:
                self._run("-I", parent, "2", "-j", chain)
            self._verify_boot_jump(parent, stage, chain)

    def _remove_boot_input_guard(self) -> None:
        self._run("-D", "INPUT", "-j", "WAYGATE_BOOT_INPUT")

    def release_first_activation_forward_guard(self) -> None:
        if self._run("-C", "FORWARD", "-j", "WAYGATE_BOOT_FWD", check=False).returncode == 0:
            self._verify_boot_jump("FORWARD", "WAYGATE_STAGE_FWD", "WAYGATE_BOOT_FWD")
            self._run("-D", "FORWARD", "-j", "WAYGATE_BOOT_FWD")
            if self._run("-C", "FORWARD", "-j", "WAYGATE_BOOT_FWD", check=False).returncode == 0:
                raise NetworkUnavailable("forward guard removal readback mismatch")

    @staticmethod
    def _rule_key(chain: str, value: str | tuple[str, ...]) -> tuple[str, ...]:
        tokens = shlex.split(value) if isinstance(value, str) else list(value)
        if isinstance(value, str) and tokens[:2] == ["-A", chain]:
            tokens = tokens[2:]
        filtered: list[str] = []
        index = 0
        while index < len(tokens):
            if tokens[index] == "--reject-with" and index + 1 < len(tokens):
                index += 2
                continue
            if tokens[index] == "-m" and index + 1 < len(tokens) and tokens[index + 1] in {"tcp", "icmp"}:
                index += 2
                continue
            if tokens[index] == "-d" and index + 1 < len(tokens) and tokens[index + 1] == "0.0.0.0/0":
                index += 2
                continue
            value = "8" if tokens[index] == "echo-request" else tokens[index]
            if set(value.split(",")) == {"ESTABLISHED", "RELATED"}:
                value = "ESTABLISHED,RELATED"
            filtered.append(value); index += 1
        return tuple(sorted(filtered))

    def _verify_boot_rules(self, chain: str, expected: tuple[tuple[str, ...], ...]) -> None:
        rules = [line for line in self._run("-S", chain).stdout.decode("utf-8", "replace").splitlines() if line.startswith(f"-A {chain} ")]
        actual_keys = [self._rule_key(chain, line) for line in rules]
        expected_keys = [self._rule_key(chain, rule) for rule in expected]
        if actual_keys != expected_keys:
            raise NetworkUnavailable("boot guard rule drift")

    def _ip_run(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(["ip", "-json", "-4", *args], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=True)
        except (OSError, subprocess.SubprocessError) as exc:
            raise NetworkUnavailable("network topology inspection failed") from exc

    def validate_topology(self, vpn_network: IPv4Network, interface: str) -> None:
        try:
            addresses = json.loads(self._ip_run("address", "show").stdout)
            routes = json.loads(self._ip_run("route", "show").stdout)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise NetworkUnavailable("network topology inspection failed") from exc
        for entry in addresses if isinstance(addresses, list) else ():
            if entry.get("ifname") == interface:
                continue
            for item in entry.get("addr_info", ()):
                if item.get("family") != "inet" or item.get("local") is None or item.get("prefixlen") is None:
                    continue
                if IPv4Network(f"{item['local']}/{item['prefixlen']}", strict=False).overlaps(vpn_network):
                    raise NetworkUnavailable("VPN subnet overlaps a non-WireGuard address")
        for route in routes if isinstance(routes, list) else ():
            destination = route.get("dst")
            if not destination or destination == "default" or route.get("dev") == interface:
                continue
            try:
                route_network = IPv4Network(destination, strict=False)
            except ValueError as exc:
                raise NetworkUnavailable("invalid IPv4 route readback") from exc
            if route_network.overlaps(vpn_network):
                raise NetworkUnavailable("VPN subnet overlaps a non-WireGuard route")

    def _default_outbound_interface(self, interface: str) -> str:
        try:
            routes = json.loads(self._ip_run("route", "show", "default").stdout)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise NetworkUnavailable("default outbound route unavailable") from exc
        candidates = [route.get("dev") for route in routes if route.get("dev") and route.get("dev") != interface]
        if not candidates:
            raise NetworkUnavailable("default outbound route unavailable")
        return candidates[0]

    def _verify_nat(self, vpn: IPv4Network, outbound_interface: str) -> None:
        expected = self._rule_key("WAYGATE_NAT", ("-s", str(vpn), "-o", outbound_interface, "-j", "MASQUERADE"))
        lines = [line for line in self._run("-t", "nat", "-S", "WAYGATE_NAT").stdout.decode("utf-8", "replace").splitlines() if line.startswith("-A WAYGATE_NAT ")]
        if [self._rule_key("WAYGATE_NAT", line) for line in lines] != [expected]:
            raise NetworkUnavailable("NAT rule readback mismatch")
        parent = [line for line in self._run("-t", "nat", "-S", "POSTROUTING").stdout.decode("utf-8", "replace").splitlines() if line.startswith("-A POSTROUTING ")]
        if parent.count("-A POSTROUTING -j WAYGATE_NAT") != 1:
            raise NetworkUnavailable("NAT jump readback mismatch")

    def _set_forwarding(self) -> None:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r", encoding="ascii") as handle:
                if handle.read().strip() == "1":
                    return
            with open("/proc/sys/net/ipv4/ip_forward", "w", encoding="ascii") as handle:
                handle.write("1\n")
            with open("/proc/sys/net/ipv4/ip_forward", "r", encoding="ascii") as handle:
                if handle.read().strip() != "1":
                    raise NetworkUnavailable("IPv4 forwarding readback mismatch")
        except (OSError, UnicodeError) as exc:
            raise NetworkUnavailable("IPv4 forwarding configuration failed") from exc

    def _verify_boot_jump(self, parent: str, stage: str, boot: str) -> None:
        rules = [line for line in self._run("-S", parent).stdout.decode("utf-8", "replace").splitlines() if line.startswith(f"-A {parent} ")]
        expected_stage, expected_boot = f"-A {parent} -j {stage}", f"-A {parent} -j {boot}"
        if len(rules) < 2 or rules[0] != expected_stage or rules[1] != expected_boot or sum(line == expected_boot for line in rules) != 1:
            raise NetworkUnavailable("boot-guard ordering drift")

    def _verify_generation(self, parent: str, chain: str, position: int, rules: Iterable[tuple[str, ...]]) -> None:
        parent_rules = [line for line in self._run("-S", parent).stdout.decode("utf-8", "replace").splitlines() if line.startswith(f"-A {parent} ")]
        expected_jump = f"-A {parent} -j {chain}"
        if len(parent_rules) < position or parent_rules[position - 1] != expected_jump or sum(line == expected_jump for line in parent_rules) != 1:
            raise NetworkUnavailable("generation jump readback mismatch")
        expected_rules = list(rules)
        child_rules = [line for line in self._run("-S", chain).stdout.decode("utf-8", "replace").splitlines() if line.startswith(f"-A {chain} ")]
        if [self._rule_key(chain, line) for line in child_rules] != [self._rule_key(chain, rule) for rule in expected_rules]:
            raise NetworkUnavailable("generation rule readback mismatch")

    def _active_generation(self, parent: str, prefix: str) -> str | None:
        listing = self._run("-S", parent, check=False)
        rules = [line for line in listing.stdout.decode("utf-8", "replace").splitlines() if line.startswith(f"-A {parent} ")]
        owned = [line for line in rules if f"-j {prefix}_" in line]
        if any(line not in {f"-A {parent} -j {prefix}_A", f"-A {parent} -j {prefix}_B"} for line in owned):
            raise NetworkUnavailable("firewall generation drift")
        expected = {generation: f"-A {parent} -j {prefix}_{generation}" for generation in ("A", "B")}
        matches = [generation for generation, rule in expected.items() if sum(line == rule for line in rules) == 1]
        if any(sum(line == rule for line in rules) > 1 for rule in expected.values()) or len(matches) > 1:
            raise NetworkUnavailable("firewall generation drift")
        return matches[0] if matches else None

    def _replace_inactive(self, table: str, chain: str, rules: Iterable[tuple[str, ...]]) -> None:
        self._ensure_chain(table, chain)
        self._run("-t", table, "-F", chain)
        for rule in rules:
            self._run("-t", table, "-A", chain, *rule)

    def validate_stage_chains(self, interface: str, client_ids: set[str] | None = None) -> None:
        for chain in ("WAYGATE_STAGE_IN", "WAYGATE_STAGE_FWD", "WAYGATE_STAGE_OUT"):
            if not self._exists("filter", chain):
                continue
            lines = [line for line in self._run("-S", chain).stdout.decode("utf-8", "replace").splitlines() if line.startswith(f"-A {chain} ")]
            for line in lines:
                tokens = shlex.split(line)[2:]
                if "--comment" not in tokens or "-j" not in tokens:
                    raise NetworkUnavailable("stage rule drift")
                comment = tokens[tokens.index("--comment") + 1]
                try:
                    tag, raw_id = comment.split(":", 1)
                    if tag != "waygate-stage" or UUID(raw_id).version != 4 or raw_id != str(UUID(raw_id)):
                        raise ValueError
                except (ValueError, IndexError):
                    raise NetworkUnavailable("stage rule drift")
                target = tokens[tokens.index("-j") + 1]
                if target not in {"REJECT", "DROP"} or "ACCEPT" in tokens:
                    raise NetworkUnavailable("stage rule drift")
                def option_value(option: str) -> str | None:
                    try:
                        return tokens[tokens.index(option) + 1]
                    except (ValueError, IndexError):
                        return None
                input_interface = option_value("-i")
                output_interface = option_value("-o")
                if chain == "WAYGATE_STAGE_IN":
                    if input_interface != interface or option_value("-s") is None or target != "REJECT" or output_interface is not None:
                        raise NetworkUnavailable("stage rule drift")
                if chain == "WAYGATE_STAGE_FWD":
                    ingress = input_interface == interface and option_value("-s") is not None and target == "REJECT" and output_interface is None
                    egress = output_interface == interface and option_value("-d") is not None and target == "DROP" and input_interface is None
                    if not (ingress or egress):
                        raise NetworkUnavailable("stage rule drift")
                if chain == "WAYGATE_STAGE_OUT" and (output_interface != interface or option_value("-d") is None or target != "DROP" or input_interface is not None):
                    raise NetworkUnavailable("stage rule drift")

    def clear_stage_rules(self, interface: str, client_ids: set[str] | None = None) -> None:
        self.validate_stage_chains(interface, client_ids)
        for chain in ("WAYGATE_STAGE_IN", "WAYGATE_STAGE_FWD", "WAYGATE_STAGE_OUT"):
            lines = [line for line in self._run("-S", chain).stdout.decode("utf-8", "replace").splitlines() if line.startswith(f"-A {chain} ")]
            for line in lines:
                tokens = shlex.split(line)[2:]
                self._run("-D", chain, *tokens)
            remaining = [line for line in self._run("-S", chain).stdout.decode("utf-8", "replace").splitlines() if line.startswith(f"-A {chain} ")]
            if remaining:
                raise NetworkUnavailable("stage rule cleanup readback mismatch")

    def _stage_rule_state(self, chain: str, expected: tuple[tuple[str, ...], ...]) -> dict[tuple[str, ...], int]:
        lines = [line for line in self._run("-S", chain).stdout.decode("utf-8", "replace").splitlines() if line.startswith(f"-A {chain} ")]
        expected_keys = {self._rule_key(chain, rule): rule for rule in expected}
        for line in lines:
            if self._rule_key(chain, line) not in expected_keys:
                raise NetworkUnavailable("stage rule drift")
        return {rule: sum(self._rule_key(chain, line) == self._rule_key(chain, rule) for line in lines) for rule in expected}

    def _client_stage_rules(self, interface: str, address: str, client_id: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
        tag = f"waygate-stage:{client_id}"
        return (("WAYGATE_STAGE_IN", ("-i", interface, "-s", f"{address}/32", "-m", "comment", "--comment", tag, "-j", "REJECT")), ("WAYGATE_STAGE_FWD", ("-i", interface, "-s", f"{address}/32", "-m", "comment", "--comment", tag, "-j", "REJECT")), ("WAYGATE_STAGE_FWD", ("-o", interface, "-d", f"{address}/32", "-m", "comment", "--comment", tag, "-j", "DROP")), ("WAYGATE_STAGE_OUT", ("-o", interface, "-d", f"{address}/32", "-m", "comment", "--comment", tag, "-j", "DROP")))

    def stage_client(self, interface: str, address: str, client_id: str) -> None:
        grouped: dict[str, list[tuple[str, ...]]] = {}
        for chain, rule in self._client_stage_rules(interface, address, client_id):
            grouped.setdefault(chain, []).append(rule)
        states = {chain: self._stage_rule_state(chain, tuple(rules)) for chain, rules in grouped.items()}
        for chain, rules in grouped.items():
            for rule in rules:
                if states[chain][rule] > 1:
                    raise NetworkUnavailable("stage rule duplicate")
                if states[chain][rule] == 0:
                    self._run("-I", chain, "1", *rule)
        for chain, rules in grouped.items():
            state = self._stage_rule_state(chain, tuple(rules))
            if any(state[rule] != 1 for rule in rules):
                raise NetworkUnavailable("stage rule install readback mismatch")

    def unstage_client(self, interface: str, address: str, client_id: str) -> None:
        grouped: dict[str, list[tuple[str, ...]]] = {}
        for chain, rule in self._client_stage_rules(interface, address, client_id):
            grouped.setdefault(chain, []).append(rule)
        for chain, rules in grouped.items():
            state = self._stage_rule_state(chain, tuple(rules))
            for rule in rules:
                if state[rule] > 1:
                    raise NetworkUnavailable("stage rule duplicate")
                if state[rule] == 1:
                    self._run("-D", chain, *rule)
        for chain, rules in grouped.items():
            state = self._stage_rule_state(chain, tuple(rules))
            if any(state[rule] != 0 for rule in rules):
                raise NetworkUnavailable("stage rule removal readback mismatch")

    def reconcile(self, interface: str, vpn: IPv4Network, api_port: int, allowed_management: list[IPv4Network], outbound_interface: str | None, client_policies: Sequence[ClientForwardPolicy]) -> None:
        if outbound_interface is None:
            outbound_interface = self._default_outbound_interface(interface)
        if outbound_interface == interface:
            raise NetworkUnavailable("outbound interface must differ from WireGuard interface")
        # Stage chains are permanently first: create/enable quarantine lands here before peer application.
        for chain, parent in (("WAYGATE_STAGE_IN", "INPUT"), ("WAYGATE_STAGE_FWD", "FORWARD"), ("WAYGATE_STAGE_OUT", "OUTPUT")):
            self._ensure_chain("filter", chain)
            self._ensure_jump("filter", parent, chain, first=True)
            self._verify_stage_jump(parent, chain)
        input_rules: list[tuple[str, ...]] = [("-i", interface, "-s", str(vpn), "-p", "icmp", "--icmp-type", "echo-request", "-d", f"{vpn.network_address + 1}/32", "-j", "ACCEPT"), ("-i", interface, "-s", str(vpn), "-j", "REJECT")]
        input_rules += [("-i", "lo", "-p", "tcp", "--dport", str(api_port), "-j", "ACCEPT")]
        input_rules += [("-p", "tcp", "--dport", str(api_port), "-s", str(cidr), "-j", "ACCEPT") for cidr in allowed_management]
        input_rules += [("-p", "tcp", "--dport", str(api_port), "-j", "REJECT"), ("-j", "RETURN")]
        forward_rules = [("-i", interface, "-s", str(vpn), "-d", blocked, "-j", "REJECT") for blocked in _BLOCKED]
        for policy in sorted(client_policies, key=lambda item: int(item.source)):
            for destination in sorted(policy.destinations, key=lambda item: (int(item.network_address), item.prefixlen)):
                forward_rules.append(("-i", interface, "-s", f"{policy.source}/32", "-o", outbound_interface, "-d", str(destination), "-j", "ACCEPT"))
        forward_rules += [("-o", interface, "-d", str(vpn), "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"), ("-i", interface, "-s", str(vpn), "-j", "REJECT"), ("-o", interface, "-d", str(vpn), "-j", "DROP"), ("-j", "RETURN")]
        # Build inactive generations before attaching them; retain an active policy until cutover.
        input_active = self._active_generation("INPUT", "WAYGATE_INPUT")
        forward_active = self._active_generation("FORWARD", "WAYGATE_FWD")
        if (input_active is None) != (forward_active is None):
            raise NetworkUnavailable("partial firewall activation")
        first_activation = input_active is None
        boot_input_attached = self._run("-C", "INPUT", "-j", "WAYGATE_BOOT_INPUT", check=False).returncode == 0
        boot_forward_attached = self._run("-C", "FORWARD", "-j", "WAYGATE_BOOT_FWD", check=False).returncode == 0
        input_boot_rules = (("-i", interface, "-s", str(vpn), "-j", "REJECT"), ("-p", "tcp", "--dport", str(api_port), "-j", "REJECT"), ("-j", "RETURN"))
        forward_boot_rules = (("-i", interface, "-s", str(vpn), "-j", "REJECT"), ("-o", interface, "-d", str(vpn), "-j", "DROP"), ("-j", "RETURN"))
        if first_activation:
            self._install_boot_guards(interface, vpn, api_port)
            boot_input_attached = True
            boot_forward_attached = True
        if boot_input_attached:
            self._verify_boot_jump("INPUT", "WAYGATE_STAGE_IN", "WAYGATE_BOOT_INPUT")
            self._verify_boot_rules("WAYGATE_BOOT_INPUT", input_boot_rules)
        if boot_forward_attached:
            self._verify_boot_jump("FORWARD", "WAYGATE_STAGE_FWD", "WAYGATE_BOOT_FWD")
            self._verify_boot_rules("WAYGATE_BOOT_FWD", forward_boot_rules)
        input_next = "A" if input_active == "B" else "B"
        forward_next = "A" if forward_active == "B" else "B"
        input_chain, forward_chain = f"WAYGATE_INPUT_{input_next}", f"WAYGATE_FWD_{forward_next}"
        self._replace_inactive("filter", input_chain, input_rules)
        self._replace_inactive("filter", forward_chain, forward_rules)
        # Parent position is authoritative: stage stays first, boot guard second while present,
        # and the new generation is ahead of all foreign/previous rules.
        input_generation_position = "3" if boot_input_attached else "2"
        forward_generation_position = "3" if boot_forward_attached else "2"
        self._run("-I", "INPUT", input_generation_position, "-j", input_chain)
        self._run("-I", "FORWARD", forward_generation_position, "-j", forward_chain)
        self._verify_generation("INPUT", input_chain, int(input_generation_position), input_rules)
        self._verify_generation("FORWARD", forward_chain, int(forward_generation_position), forward_rules)
        if input_active is not None:
            self._run("-D", "INPUT", "-j", f"WAYGATE_INPUT_{input_active}")
            remaining_input = [line for line in self._run("-S", "INPUT").stdout.decode("utf-8", "replace").splitlines() if line.startswith("-A INPUT ")]
            if sum(line == f"-A INPUT -j {input_chain}" for line in remaining_input) != 1 or any(line == f"-A INPUT -j WAYGATE_INPUT_{input_active}" for line in remaining_input):
                raise NetworkUnavailable("old INPUT generation removal mismatch")
        if forward_active is not None:
            self._run("-D", "FORWARD", "-j", f"WAYGATE_FWD_{forward_active}")
            remaining_forward = [line for line in self._run("-S", "FORWARD").stdout.decode("utf-8", "replace").splitlines() if line.startswith("-A FORWARD ")]
            if sum(line == f"-A FORWARD -j {forward_chain}" for line in remaining_forward) != 1 or any(line == f"-A FORWARD -j WAYGATE_FWD_{forward_active}" for line in remaining_forward):
                raise NetworkUnavailable("old FORWARD generation removal mismatch")
        if boot_input_attached:
            self._verify_boot_jump("INPUT", "WAYGATE_STAGE_IN", "WAYGATE_BOOT_INPUT")
            self._remove_boot_input_guard()
            self._verify_generation("INPUT", input_chain, 2, input_rules)
        self._replace_inactive("nat", "WAYGATE_NAT", [("-s", str(vpn), "-o", outbound_interface, "-j", "MASQUERADE")])
        self._ensure_jump("nat", "POSTROUTING", "WAYGATE_NAT", first=False)
        self._verify_nat(vpn, outbound_interface)
        self._set_forwarding()
