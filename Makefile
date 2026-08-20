PY := python3

.PHONY: check test lint fixtures clean
check: test fixtures
test:
	$(PY) -m unittest discover -s tests -p 'test_*.py' -v
fixtures:
	./tests/run-tests.sh
clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
