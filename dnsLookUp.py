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


def print_record(record_type, value):
    print(f"  [{record_type:>6}] {value}")


def basicIP_lookUp(domain):
    print_section("Basic IP Lookup ")
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"  Domain : {domain}")
        print(f"  IPv4   : {ip_address}")
        return ip_address
    except socket.gaierror as e:
        print(f"  error  : couldn`t get '{domain}' -> {e}")
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
        print(f"  error  : couldn`t get '{domain}' -> {e}")
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
        print(f"  error  : couldn`t get '{domain}' -> {e}")
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


def dns_record_query(domain):
    if not Dns_py_available:
        print_section("Advanced DNS Records")
        print("  NeedED Library not available.")
        print("  skipping advanced record lookup")
        return
    record_types = ["A", "AAAA", "MX", "NS", "CANME", "TXT", "SOA"]

    print_section("DNS Record Lookup by dnspython")
    print(f"  Records for domain : {domain}\n")

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                if rtype == "MX":
                    print_record(
                        rtype, f"{rdata.exchange} (priority : {rdata.preference})"
                    )

                elif rtype == "SOA":
                    print_record(
                        rtype,
                        f"Primary Ns : {rdata.rname}, \n"
                        f"           Admin : {rdata.rname}, \n"
                        f"           Serial : {rdata.serial} ",
                    )

                elif rtype == "txt":
                    txt_value = b"".join(rdata.strings).decode(
                        "utf-8", errors="replace"
                    )
                    print_record(rtype, txt_value)
                else:
                    print_record(rtype, str(rdata))
        except dns.resolver.NoAnswer:
            print_record(rtype, "(No Record found)")
        except dns.resolver.NXDOMAIN:
            print_record(rtype, f"Domain {domain} does not exist")
            break
        except dns.resolver.Timeout:
            print_record(rtype, "timedout")
        except dns.resolver.NoNameservers:
            print_record(rtype, "(No nameservers available)")
        except Exception as e:
            print_record(rtype, f"error : {e}")


def reverse_dns_advanced(ip_address):
    if not Dns_py_available:
        return
    print_section(f"Reverse DNS via PTR recored for {ip_address}")
    try:
        revName = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(revName, "PTR")
        for rdata in answers:
            print(f"  PTR : {rdata}")
    except Exception as e:
        print(f"  error : {e}")


def DomainInfo_Summary(domain):
    print_section(f"Domain Information Summary: {domain}")
    try:
        ip = socket.gethostbyname(domain)
        print(f"  Primary IPv4      : {ip}")
    except socket.gaierror:
        print(f"  IP unresolvable")
        return

    try:
        fqdn = socket.getfqdn(domain)
        print(f"  FQDN              : {fqdn}")
    except Exception:
        pass

    try:
        _, _, ip_list = socket.gethostbyname_ex(domain)
        if len(ip_list) > 1:
            print(f"  All IPv4 adresses : {' , '.join(ip_list)}")
    except Exception:
        pass

    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET6)
        ipv6_addrs = list({r[4][0] for r in results})
        if ipv6_addrs:
            for addr in ipv6_addrs:
                print(f"  IPv6 address      : {addr}")

    except Exception:
        pass

    try:
        (
            revHost,
            _,
            _,
        ) = socket.gethostbyaddr(ip)
        print(f"  Reverse Hostname : {revHost}")

    except Exception:
        print(f"  Reverse Hostname : not available")


def showMenu():
    print("\n  Select an option: ")
    print(" " + "*" * 40)
    print("  [1] Basic Ip Lookup")
    print("  [2] Extended Ip Lookup")
    print("  [3] Address Info")
    print("  [4] Reverse DNS Lookup")
    print("  [5] DNS Record Lookup")
    print("  [6] Full Domain Report")
    print("  [7] Change Domain")
    print("  [0] Exit")
    print(" " + "*" * 40)


def getDomain():
    while True:
        domain = input("\n  Enter Domain Name : ").strip()
        if domain:
            for prefix in ("http://", "https://", "www."):
                if domain.startswith(prefix):
                    domain = domain[len(prefix) :]
            domain = domain.rstrip("/")
            return domain
        print("  Please enter a valid domain name. ")


def run_it():
    if not Dns_py_available:
        print("  dnsPython is not installed.")

    domain = getDomain()
    print(f"\n  Current domain : {domain}")

    while True:
        showMenu()
        choice = input("\n  >> ").strip()

        match choice:
            case "1":
                basicIP_lookUp(domain)

            case "2":
                extendedIP_lookUp(domain)

            case 3:
                add_info_lookUp(domain)

            case "4":
                ip = input("  Enter IP Address for reverse lookup : ").strip()
                if not ip:
                    try:
                        ip = socket.gethostbyname(domain)
                        print(f"  Using resolved IP: {ip}")
                    except socket.gaierror:
                        print(" Could not resolve domain for ip Address.")
                        continue
                reverse_dns_lookup(ip)
                reverse_dns_advanced(ip)

            case "5":
                dns_record_query(domain)

            case "6":
                print(f"\n  Generating Full report for : {domain}")
                print(f"  {'.'*40}")
                basicIP_lookUp(domain)
                extendedIP_lookUp(domain)
                add_info_lookUp(domain)
                dns_record_query(domain)
                try:
                    ip = socket.gethostbyname(domain)
                    reverse_dns_lookup(ip)
                    reverse_dns_advanced(ip)
                except socket.gaierror:
                    pass
                DomainInfo_Summary(domain)

            case "7":
                domain = getDomain()
                print(f"  current domain : {domain}")

            case "0":
                print("byeeeee!!!!!!!!!")
                break

            case _:
                print("  Please enter valid option.")


def run_cli(domain):
    print(f"  Target Domain : {domain}\n")
    basicIP_lookUp(domain)
    extendedIP_lookUp(domain)
    add_info_lookUp(domain)
    dns_record_query(domain)

    try:
        ip = socket.gethostbyname(domain)
        reverse_dns_lookup(ip)
        reverse_dns_advanced(ip)
    except socket.gaierror:
        pass
    DomainInfo_Summary(domain)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        for prefix in ("http://", "https://", "www."):
            if target.startswith(prefix):
                target = target[len(prefix) :]
        target = target.rstrip("/")
        run_cli(target)

    else:
        run_it()
