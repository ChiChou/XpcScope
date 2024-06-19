# XpcScope

Yet another xpc sniffer

## dependencies

Written in python, should support Windows and Linux as well.

* python >=3.10, < 3.13
* poetry

Here is the setup instructions on macOS.

```
brew install python3  # requires python >=3.10
brew install pipx  # since python 3.11, directly install package will yield an externally-managed-environment error
pipx install poetry # the real venv manager we need
```

Then setup the virtual env:

```
poetry install
```

Build frida agent:

```
make agent

# on Windows or systems without make, manually the command in Makefile
# frida-compile src\frida\agent\index.ts > src\frida\_agent.js
```

Build resource files:

```
make res  # or manually run the command in Makefile
# pyside6-rcc -o src/xpcscope/res.py assets/resources.qrc
```

## Run

First modify the `get_target` function in `bin/xpcscope` for your target.

```
poetry shell
python3 bin/xpcscope
```

![screenshot](assets/screenshot.png)
