from pathlib import Path
from typing import Callable

from frida.core import Script, Session


def load_script(session: Session, on_message: Callable[[dict, bytes], None]) -> Script:
    source = Path(__file__).parent.parent / 'frida' / '_agent.js'
    with source.open('r', encoding='utf8') as f:
        script = session.create_script(f.read())

    script.on('message', on_message)
    script.load()
    return script

