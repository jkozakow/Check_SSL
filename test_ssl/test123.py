from certcheck import certcheck

ip_input = "216.58.209.0-216.58.209.2"
ips, certs = certcheck(ip_input)

print(ips)
print(certs)