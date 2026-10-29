"""Offline host normalization and Public Suffix List matching (stdlib only)."""
from functools import lru_cache
import ipaddress
from pathlib import Path
import re
import socket


@lru_cache(maxsize=1)
def _suffixes():
    return {line.encode('idna').decode('ascii').lower()
            for line in Path(__file__).with_name('public_suffix_list.dat').read_text(encoding='utf-8').splitlines()
            if line and not line.startswith('//')}


def normalize_host(host):
    host = host.strip().rstrip('.').strip('[]')
    try:
        return socket.inet_ntoa(socket.inet_aton(host))
    except OSError:
        pass
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        pass
    host = host.encode('idna').decode('ascii').lower().rstrip('.')
    if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
                                  for p in host.split('.')):
        raise ValueError('invalid host')
    return host


def _suffix_count(labels):
    rules, count = _suffixes(), 1
    for i in range(len(labels)):
        tail = '.'.join(labels[i:])
        if '!' + tail in rules:
            return len(labels) - i - 1
        if tail in rules or i and '*.' + tail in rules:
            count = max(count, len(labels) - i + (1 if i and '*.' + tail in rules else 0))
    return count


def registrable_domain(host):
    host = normalize_host(host)
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        labels = host.split('.')
        return '.'.join(labels[-(_suffix_count(labels) + 1):])


def domain_pattern(value):
    """A host or leading *. host; refuse public suffixes and arbitrary globs."""
    host = normalize_host(value.removeprefix('*.'))
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split('.')
        if len(labels) <= _suffix_count(labels):
            raise ValueError('a public suffix is not a host pattern')
    return host


def matches(host, pattern):
    host, pattern = normalize_host(host), domain_pattern(pattern)
    if host == pattern:
        return True
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return registrable_domain(host) == registrable_domain(pattern) and host.endswith('.' + pattern)
