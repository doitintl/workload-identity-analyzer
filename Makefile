venv-create:
	pip install virtualenv
	python3 -m venv venv

venv-activate:
	@echo '. venv/bin/activate'

venv-deactive:
	@echo 'deactivate'

clean:
	rm -rf dist

build: clean
	pip install build
	python3 -m build

install: build
	pip install dist/*.whl

pypi-upload:
	pip install twine
	twine upload dist/*

unittest:
	python3 -m unittest discover
