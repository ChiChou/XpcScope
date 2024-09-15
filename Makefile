RESPY = src/xpcscope/res.py
RES = assets/resources.qrc

res:
	pyside6-rcc -o $(RESPY) $(RES)

install:
	pip install -e .

run:
	python bin/xpcscope

agent:
	frida-compile src/frida/agent/index.ts > src/frida/_agent.js

prepare: install res agent
	echo OK