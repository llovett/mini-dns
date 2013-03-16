#!/usr/bin/env python

from subprocess import check_output, CalledProcessError

TESTS = ["mspiggy.cs.oberlin.edu",
         "occs.cs.oberlin.edu",
         "cs.ucsd.edu",
         "www.nus.edu",
         "www.cornell.edu",
         "www.yahoo.com.tw",
         "www.yahoo.com",
         "www.prothom-alo.com",
         "www.creditunion1.org",
         "128.30.76.78",
         "63.111.24.121"]

# Pairs of nameserver, expected exit status of ./hw3
NAMESERVERS = [("132.162.1.31",0),
               ("127.0.0.1",1)]

def test(hostname,nameserver=None):
    real_ip = check_output(['host', '-tA', hostname]).split()[-1].strip('. ')
    if not nameserver:
        prog_ip = check_output(['./hw3', '-i', hostname]).split()[-1].strip('. ')
    else:
        prog_ip = check_output(['./hw3',
                                '-n', nameserver,
                                '-i', hostname]).split()[-1].strip('. ')

    if real_ip != prog_ip:
        print "[FAILURE] %s resolves to %s, not %s."%(hostname, real_ip, prog_ip)
    else:
        print "[SUCCESS] %s resolves to %s."%(hostname, prog_ip)

if __name__ == '__main__':
    for case in TESTS:
        test(case)
    for case in TESTS:
        for ns in NAMESERVERS:
            try:
                test(case,nameserver=ns[0])
            except CalledProcessError:
                if ns[1] > 0:
                    print "[SUCCESS] Could not contact bogus nameserver."
                else:
                    print "[FAILURE] Should have been able to contact %s."%ns[0]

