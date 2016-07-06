from netaddr import IPRange, IPSet, IPAddress
import ssl, OpenSSL, socket


def certcheck(ip_input):
    certs = []
    ips = ipranges(ip_input)
    try:
        for idx, ip in enumerate(ips):
            ip, cert = extractcert(ip)
            certs.append(cert)
    except Exception as e:
        print(e)
    try:
        ips, cert = extractcert(ips)
        certs.append(cert)
    except Exception as e:
        print(e)
    return ips, certs

def extractcert(ip):
    try:
        sock = socket.socket()
        sock.settimeout(0.1)            #filter hosts with long response
        sock.connect((str(ip), 443))    #check if host responses
        cert = ssl.get_server_certificate((str(ip), 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        for i in range(x509.get_extension_count()):
            if x509.get_extension(i).get_short_name() == b'subjectAltName':
                alt_names = x509.get_extension(i)
                
            else:
                pass
        
        subject = x509.get_subject().CN
        issuer = x509.get_issuer().CN
        sign_algorithm = x509.get_signature_algorithm()
        valid_from = str(x509.get_notBefore(), encoding="utf-8")
        valid_from = valid_from[:4] + "/" + valid_from[4:6] + "/" + valid_from[6:8] + " " + valid_from[8:10] + ":" + valid_from[10:12] + ":" + valid_from[12:14]
        valid_until = str(x509.get_notAfter(), encoding="utf-8")
        valid_until = valid_until[:4] + "/" + valid_until[4:6] + "/" + valid_until[6:8] + " " + valid_until[8:10] + ":" + valid_until[10:12] + ":" + valid_until[12:14]
        cert = ([str(ip), subject, issuer, sign_algorithm, valid_from, valid_until, str(alt_names)])
    except Exception as e:
        pass
    return ip, cert

def ipranges(ip_input):
    ips = []
    ip_input = ip_input.replace(" ", "")
    if '/' in ip_input:
        if ',' in ip_input:
            ip_input_ranges = ip_input.split(',')
            for ip_range in ip_input_ranges:
                for ip in IPSet([ip_range]):
                    ips.append(ip)
        else:
            ips = IPSet([ip_input])
    elif '-' in ip_input:
        if ',' in ip_input:
            ip_input_ranges = ip_input.split(',')
            for ip_range in ip_input_ranges:
                ip_split = ip_range.split("-")
                ip_range_temp = IPRange(ip_split[0], ip_split[1])
                for idx, ip in enumerate(ip_range_temp):
                    ips.append(ip_range_temp[idx])
        else:
            ip_split = ip_input.split("-")
            ips = IPRange(ip_split[0], ip_split[1])
    else:
        ips = IPAddress(ip_input)
    return ips
    
