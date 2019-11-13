TCP_COMMON_PORTS = {
    20: 'ftp',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    80: 'http',
    110: 'pop3',
    135: 'msrpc',
    137: 'nbt',
    138: 'nbt',
    139: 'nbt',
    143: 'imap4',
    161: 'snmp',
    162: 'snmp-trap',
    389: 'ldap',
    443: 'https',
    445: 'microsoft-ds',
    636: 'ldaps',
    993: 'imaps',
    995: 'pop3s',
    1723: 'pptp',
    3306: 'mysql',
    3389: 'rdp',
    8080: 'http-alt'
}

UDP_COMMON_PORTS = {
    53: 'dns',
    67: 'dhcps',
    68: 'dhcpc',
    69: 'tftp',
    88: 'xbox',
    123: 'ntp',
    137: 'netbios-ns',
    138: 'netbios-dgm',
    139: 'netbios-ssn',
    161: 'snmp',
    162: 'snmp-trap',
    445: 'microsoft-ds',
    500: 'isakmp',
    631: 'ipp'
}

HTTP_S_PORTS = {80, 443, 8080}

SMB_PORTS = {137, 138, 139, 445}

SNMP_PORTS = {161, 162}
