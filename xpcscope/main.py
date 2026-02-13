#!/usr/bin/env python3

from pathlib import Path
from typing import Callable

import json
import signal
import sys
import os
import shutil

import frida

from xpcscope.pcap import Pcap


PROJECT_ROOT = Path(__file__).parent.parent

def deploy_plugin():
    # install dissector to Wireshark
    # if windows
    def location():
        if sys.platform == 'win32':
            return Path(os.environ['APPDATA']) / 'Wireshark' / 'plugins'
        return Path.home() / '.local' / 'lib' / 'wireshark' / 'plugins'

    plugins = location()
    if not plugins.exists():
        plugins.mkdir(parents=True, exist_ok=True)

    shutil.copy(PROJECT_ROOT / 'lua' / 'xpc.lua', plugins / 'xpc.lua')
    json_dir = plugins / 'json'
    if not json_dir.exists():
        json_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(PROJECT_ROOT / 'lua' / 'json' / 'json.lua', json_dir / 'json.lua')

def tool(get_target: Callable[[], frida.core.Session]):
    session = get_target()

    source = PROJECT_ROOT / 'agent' / '_agent.js'
    try:
        with source.open('r', encoding='utf8') as f:
            script = session.create_script(f.read())
    except FileNotFoundError:
        sys.stderr.write(f'frida agent {source} not found\n')
        return

    pcap = Pcap()

    def on_message(message: dict, data: bytes):
        if message['type'] == 'send':
            not_null_data = data if data is not None else b''
            metadata = json.dumps(message['payload'])
            joint = metadata.encode('utf8') + not_null_data
            ok = pcap.write(joint, len(not_null_data))
            if not ok:
                os.kill(os.getpid(), signal.SIGINT)
                return

        elif message['type'] == 'error' and 'description' in message and \
                'unable to find module \'libobjc.A.dylib\'' in message['description']:
            sys.stderr.write(
                'Script successfully injected but the target does not have ObjC runtine.\n')
            sys.stderr.write('You are likely injecting to a wrong platform binary.\n')
            os.kill(os.getpid(), signal.SIGINT)
            return
        else:
            sys.stderr.write(f'{message}\n')

    script.on('message', on_message)
    script.load()
    pcap.write_header()
    script.exports_sync.start()
    # name, pid = script.exports_sync.name_and_pid()
    # sys.stderr.write(f'attached to {name}({pid})\n')

    try:
        input()
    except KeyboardInterrupt:
        pass
    finally:
        script.unload()
        session.detach()


def cli():
    deploy_plugin()

    if len(sys.argv) == 2:
        name = sys.argv[1]
    else:
        name = "target"

    import os
    sys.path.append(os.path.dirname(name))
    try:
        loader = __import__(os.path.basename(name))
    except ImportError:
        sys.stderr.write(
            "You need to put target.py in current directory to attach\n")
        sys.exit(1)

    try:
        if not tool(getattr(loader, 'attach')):
            sys.exit(1)
    except AttributeError:
        sys.stderr.write(f"Module {name} does not have an 'attach' function\n")
        sys.exit(1)


if __name__ == "__main__":
    cli()
