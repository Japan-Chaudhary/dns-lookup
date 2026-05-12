import socket
import sys

try:
    import dns.resolver
    import dns.reversename

    Dns_py_available = True
except ImportError:
    Dns_py_available = False


def print_section(title):
    print(f"\n{'*'*60}")
    print(f"  {title}")
    print(f"\n{'*'*60}")


def basicIP_lookUp(domain):
    print_section("Basic IP Lookup ")
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"  Domain : {domain}")
        print(f"  IPv4   : {ip_address}")
        return ip_address
    except socket.gaierror as e:
        print(f"  error  : couldn\`t get '{domain}' -> {e}")
        return None


def extendedIP_lookUp(domain):
    print_section("Extented IP Lookup")
    try:
        hostname, aliases, ip_list = socket.gethostbyname_ex(domain)
        print(f"  Hostname    : {hostname}")
        if aliases:
            for alias in aliases:
                print(f"  Alias       : {alias}")
        else:
            print(f"  Aliases     : none")
        for ip in ip_list:
            print(f"  IPv4 Address  : {ip}")
        return hostname, aliases, ip_list
    except socket.gaierror as e:
        print(f"  error  : couldn\`t get '{domain}' -> {e}")
        return None, [], []


def add_info_lookUp(domain):
    print_section("Address Info Lookup")
    try:
        result = socket.getaddrinfo(domain, None)
        seen = set()
        for family, socktype, proto, canonname, sockaddr in result:
            ip = sockaddr[0]
            if ip in seen:
                continue
            seen.add(ip)
            family_name = "IPv4" if family == socket.AF_INET else "IPv6"
            print(f"  {family_name:>4} : {ip}")
        return list(seen)
    except socket.gaierror as e:
        print(f"  error  : couldn\`t get '{domain}' -> {e}")
        return []


def reverse_dns_lookup(ip_address):
    print_section(f"Reverse DNS lookup for : {ip_address}")
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip_address)
        print(f"  IP          : {ip_address}")
        print(f"  hostname    : {hostname}")
        if aliases:
            for alias in aliases:
                print(f"  alias       : {alias}")
            return hostname
    except socket.herror as e:
        print(f"  error     : Reverse lookup failed for {ip_address} - {e}")
        return None
    except socket.gaierror as e:
        print(f" error      : Invalid address {ip_address} - {e}")
        return None


if __name__ == "__main__":
    ...
