import validators


def is_host_valid(host):
    if validators.ipv4(host) or validators.domain(host):
        return True

    return False
