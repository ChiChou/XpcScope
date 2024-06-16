RESPY = src/xpcscope/res.py
RES = assets/resources.qrc

res:
	poetry run pyside6-rcc -o $(RESPY) $(RES)

install:
	poetry install

run:
	poetry run python bin/xpcscope

agent:
	poetry run frida-compile src/frida/agent/index.ts > src/frida/_agent.js

prepare: install res agent
	echo