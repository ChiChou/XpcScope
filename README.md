# XpcScope

Yet another xpc sniffer

## dependencies

Written in python, should support Windows and Linux as well.

* python >=3.10

Here is the setup instructions on macOS.

```shell
brew install python3                # requires python >=3.10
python3 -m venv .venv               # initialize virtual environment
source .venv/bin/activate           # active venv shell
pip install -e .                    # install all dependencies
```

Build frida agent:

```shell
make prepare

# on Windows or systems without make, manually type the following commands from Makefile
#
# frida-compile agent\src\index.ts > agent\_agent.js
```

## Run

I am too lazy to adapt the cli options from frida, so simply write your attach logic in `target.py` under current directory.

An example script is provided in `target.example.py`

With venv activated:

```shell
xpcscope target.py | wireshark -k -i -
```

Or if you have [uv](https://docs.astral.sh/uv/)

```shell
uv run xpcscope target.py | wireshark -k -i -
```
