#!/usr/bin/env bash

brew install pyenv
pyenv local 3.9.5
python -m venv testbed
source testbed/bin/activate
pip install pynacl securesystemslib
./cjson.py
