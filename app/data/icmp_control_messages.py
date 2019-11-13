ICMP_TYPES = {
    "DST_UNREACHABLE": 3
}

ICMP_DST_UNREACHABLE_CODES = {
    "DST_NET_UNREACHABLE": 0,
    "DST_HOST_UNREACHABLE": 1,
    "DST_PROTOCOL_UNREACHABLE": 2,
    "DST_PORT_UNREACHABLE": 3,
    "FRAG_REQ_DF_FLAG_SET": 4,
    "SRC_ROUTE_FAILED": 5,
    "DST_NET_UNK": 6,
    "DST_HOST_UNK": 7,
    "SRC_HOST_ISOLATED": 8,
    "NET_ADMIN_PROHIBITED": 9,
    "HOST_ADMIN_PROHIBITED": 10,
    "NET_UNREACHABLE_FOR_TOS": 11,
    "HOST_UNREACHABLE_FOR_TOS": 12,
    "COMM_ADMIN_PROHIBITED": 13,
    "HOST_PRECEDENCE_VIOLATION": 14,
    "PRECEDENCE_CUTOFF_IN_EFFECT": 15
}

SS_UNREACHABLE_ERROR = {
    "type": ICMP_TYPES["DST_UNREACHABLE"],
    "codes": [
        ICMP_DST_UNREACHABLE_CODES["DST_HOST_UNREACHABLE"],
        ICMP_DST_UNREACHABLE_CODES["DST_PROTOCOL_UNREACHABLE"],
        ICMP_DST_UNREACHABLE_CODES["DST_PORT_UNREACHABLE"],
        ICMP_DST_UNREACHABLE_CODES["NET_ADMIN_PROHIBITED"],
        ICMP_DST_UNREACHABLE_CODES["HOST_ADMIN_PROHIBITED"],
        ICMP_DST_UNREACHABLE_CODES["COMM_ADMIN_PROHIBITED"]
    ]
}

UDPS_UNREACHABLE_ERROR = {
    "type": ICMP_TYPES["DST_UNREACHABLE"],
    "code": ICMP_DST_UNREACHABLE_CODES["DST_PORT_UNREACHABLE"]
}

OTHER_UDPS_UNREACHABLE_ERROR = {
    "type": ICMP_TYPES["DST_UNREACHABLE"],
    "codes": [
        ICMP_DST_UNREACHABLE_CODES["DST_HOST_UNREACHABLE"],
        ICMP_DST_UNREACHABLE_CODES["DST_PROTOCOL_UNREACHABLE"],
        ICMP_DST_UNREACHABLE_CODES["NET_ADMIN_PROHIBITED"],
        ICMP_DST_UNREACHABLE_CODES["HOST_ADMIN_PROHIBITED"],
        ICMP_DST_UNREACHABLE_CODES["COMM_ADMIN_PROHIBITED"]
    ]
}