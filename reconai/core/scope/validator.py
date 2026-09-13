"""Scope validation — checks whether a target/action is within authorized scope."""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from urllib.parse import urlparse

from reconai.core.scope.models import ScopeDefinition


class ScopeValidator:
    """Validates targets against the defined scope.

    This is the security gate — every active module must pass through here.
    """

    def __init__(self, scope: ScopeDefinition):
        self._scope = scope
        self._ip_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._excluded_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._compile_networks()

    def _compile_networks(self) -> None:
        """Pre-compile IP networks for efficient checking."""
        for ip_str in self._scope.ips:
            try:
                self._ip_networks.append(ipaddress.ip_network(ip_str, strict=False))
            except ValueError:
                pass

        for ip_str in self._scope.excluded_ips:
            try:
                self._excluded_networks.append(ipaddress.ip_network(ip_str, strict=False))
            except ValueError:
                pass

    def is_domain_allowed(self, domain: str) -> bool:
        """Check if a domain is within scope."""
        domain = domain.lower().strip().rstrip(".")

        # Check exclusions first
        for excluded in self._scope.excluded_domains:
            if self._domain_matches(domain, excluded):
                return False

        # Check allowed domains
        if not self._scope.domains:
            return False

        for allowed in self._scope.domains:
            if self._domain_matches(domain, allowed):
                return True

        return False

    def is_ip_allowed(self, ip_str: str) -> bool:
        """Check if an IP address is within scope."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        # Check exclusions first
        for net in self._excluded_networks:
            if ip in net:
                return False

        # If no IP scope defined, allow IPs that resolve from in-scope domains
        if not self._ip_networks:
            return True

        for net in self._ip_networks:
            if ip in net:
                return True

        return False

    def is_port_allowed(self, port: int) -> bool:
        """Check if a port is within scope."""
        if port in self._scope.excluded_ports:
            return False

        # Empty allowed ports = all ports allowed
        if not self._scope.ports:
            return True

        return port in self._scope.ports

    def is_url_allowed(self, url: str) -> bool:
        """Check if a URL's host is within scope."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False

            # Check if it's an IP
            try:
                ipaddress.ip_address(hostname)
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                return self.is_ip_allowed(hostname) and self.is_port_allowed(port)
            except ValueError:
                pass

            # It's a domain
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            return self.is_domain_allowed(hostname) and self.is_port_allowed(port)
        except Exception:
            return False

    def is_target_allowed(self, target: str) -> bool:
        """Universal check — works with domains, IPs, URLs, and host:port combos."""
        target = target.strip()

        # URL?
        if "://" in target:
            return self.is_url_allowed(target)

        # host:port?
        if ":" in target:
            parts = target.rsplit(":", 1)
            host = parts[0]
            try:
                port = int(parts[1])
                return self._check_host(host) and self.is_port_allowed(port)
            except ValueError:
                pass

        return self._check_host(target)

    def _check_host(self, host: str) -> bool:
        """Check if a host (domain or IP) is allowed."""
        try:
            ipaddress.ip_address(host)
            return self.is_ip_allowed(host)
        except ValueError:
            return self.is_domain_allowed(host)

    @staticmethod
    def _domain_matches(domain: str, pattern: str) -> bool:
        """Check if a domain matches a pattern (supports wildcards)."""
        pattern = pattern.lower().strip()
        domain = domain.lower().strip()

        if pattern == domain:
            return True

        # Wildcard matching: *.example.com
        if pattern.startswith("*."):
            base = pattern[2:]
            return domain == base or domain.endswith(f".{base}")

        # fnmatch for other patterns
        return fnmatch.fnmatch(domain, pattern)
