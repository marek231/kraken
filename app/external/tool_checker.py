from shutil import which


def is_tool_available(name):
    return which(name) is not None
