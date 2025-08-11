import frida


def attach() -> frida.core.Session:
    return frida.get_local_device().attach('example')
