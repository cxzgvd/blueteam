import webbrowser

def analyze_ip(ip):
    urls = [
        f"https://ipinfo.io/{ip}",
        f"https://whois.domaintools.com/{ip}",
        f"https://mxtoolbox.com/SuperTool.aspx?action=arin%3a{ip}",
        f"https://otx.alienvault.com/indicator/ip/{ip}",
        f"https://talosintelligence.com/reputation_center/lookup?search={ip}",
        f"https://www.abuseipdb.com/check/{ip}",
        f"https://www.virustotal.com/gui/ip-address/{ip}",
        f"https://www.shodan.io/host/{ip}",
        f"https://www.ipvoid.com/ip-blacklist-check/{ip}",
        f"https://dnslytics.com/ip/{ip}",
        f"https://viewdns.info/reverseip/?host={ip}",
        f"https://viz.greynoise.io/ip/{ip}",
        f"https://urlhaus.abuse.ch/host/{ip}",
        f"https://urlscan.io/ip/{ip}"
    ]
    for url in urls:
        webbrowser.open(url, new=1)

def analyze_domain(domain):
    urls = [
        f"https://whois.domaintools.com/{domain}",
        f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}",
        f"https://dnsdumpster.com/{domain}",
        f"https://securitytrails.com/domain/{domain}/dns",
        f"https://www.virustotal.com/gui/domain/{domain}",
        f"https://sitecheck.sucuri.net/results/{domain}",
        f"https://centralops.net/co/DomainDossier.aspx?dom_whois=true&dom_dns=true&dom_mx=true&addr_in=true&dom_b2b=true&dom_b2c=true&net_whois=true&xfer=true&target={domain}",
        f"https://dnslookup.online/{domain}",
        f"https://www.robtex.com/dns-lookup/{domain}",
        f"https://securitytrails.com/domain/{domain}/dns",
        f"https://viz.greynoise.io/domain/{domain}",
        f"https://urlhaus.abuse.ch/host/{domain}",
        f"https://talosintelligence.com/reputation_center/lookup?search={domain}",
        f"https://urlscan.io/domain/{domain}"
    ]
    for url in urls:
        webbrowser.open(url, new=1)

def main():
    choice = input("Wybierz 'ip' lub 'domena': ").strip().lower()
    if choice == 'ip':
        ip = input("Podaj adres IP: ").strip()
        analyze_ip(ip)
    elif choice == 'domena':
        domain = input("Podaj domenę: ").strip()
        analyze_domain(domain)
    else:
        print("Niepoprawny wybór. Proszę wybrać 'ip' lub 'domena'.")

if __name__ == "__main__":
    main()
