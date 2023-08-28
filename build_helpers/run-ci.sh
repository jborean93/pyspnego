#!/bin/bash -ex

# Set by GHA setup-python
if [[ -n "${pythonLocation}" ]]; then
    PATH="${pythonLocation}/bin:${PATH}"
fi

source ./build_helpers/lib.sh
lib::setup::system_requirements
lib::setup::python_requirements
lib::sanity::run
lib::tests::run
