import frida


def get() -> frida.core.Session:
    return frida.get_local_device().attach('example')
