from django.shortcuts import render
from netaddr import IPRange, IPSet
from . import certcheck


def index(request):
    context = {}
    return render(request, 'test_ssl/index.html', context)


def submit(request):
    ip_input = request.POST['iprange']
    ips, certs = certcheck.certcheck(ip_input)
    return render(request, 'test_ssl/result.html', {'ips': ips, 'certs': certs})
