# XpcScope

Yet another xpc sniffer

![Screenshot](assets/screenshot.png)

## Setup

```shell
git clone --recurse-submodules https://github.com/ChiChou/XpcScope.git
```

```shell
python3 -m venv .venv                                 # initialize virtual environment
source .venv/bin/activate                             # active venv shell
pip install -e .                                      # install all dependencies
frida-compile agent/src/index.ts -o agent/_agent.js   # build frida agent
```

## Run

I am too lazy to adapt the cli options from frida, so simply write your attach logic in `target.py` under current directory.

An example script is provided in `target.example.py`

With venv activated:

```shell
xpcscope target | wireshark -k -i -
```

Or if you have [uv](https://docs.astral.sh/uv/)

```shell
uv run xpcscope target | wireshark -k -i -
```
