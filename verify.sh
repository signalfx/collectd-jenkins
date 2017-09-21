#!/bin/bash
flake8 --max-line-length=120 jenkins.py
if [ "$?" -ne 0 ]; then
    exit 1;
fi
py.test test_jenkins.py
