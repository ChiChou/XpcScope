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
cd agent && npm install && npm run build              # install frida agent dependencies and build the agent
```

Now I addded a `./setup.sh` for convenience, you can simply run it to do all the above steps.

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

## Wireshark Display Filters

The dissector registers the following fields for filtering:

| Field | Type | Description |
|-------|------|-------------|
| `xpc.name` | string | XPC service name |
| `xpc.dir` | string | `>` (sent) or `<` (received) |
| `xpc.event` | string | `sent` or `received` |
| `xpc.peer` | int | Remote peer PID |
| `xpc.msgtype` | string | `dictionary`, `nsxpc`, etc. |
| `xpc.sel` | string | NSXPC selector (NSXPC only) |

Examples:

```
xpc.name == "com.apple.windowserver"
xpc.name contains "apple"
xpc.dir == ">"
xpc.peer == 372
xpc.msgtype == "nsxpc"
xpc.sel contains "fetch"
```
