RESPY = src/xpcscope/res.py
RES = assets/resources.qrc

res:
	poetry run pyside6-rcc -o $(RESPY) $(RES)

install:
	poetry install

run:
	poetry run python bin/xpcscope

agent:
	cd backend/frida && npm i && npm run build

prepare: install res agent
	echo