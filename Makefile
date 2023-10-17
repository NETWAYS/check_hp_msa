.PHONY: lint test

lint:
	python -m pylint check_hp_msa.py

test:
	python -m unittest -v test_check_hp_msa.py
coverage:
	python -m coverage run -m unittest test_check_hp_msa.py
	python -m coverage report -m --include check_hp_msa.py
