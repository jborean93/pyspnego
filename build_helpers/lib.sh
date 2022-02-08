#!/bin/bash


lib::setup::debian_requirements() {
    echo "Installing Debian based pre-requisites"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update

    if [ x"$GSSAPI_PROVIDER" = "xheimdal" ]; then
        echo "Installing Heimdal packages for Debian"
        apt-get -y install \
            heimdal-{clients,dev,kdc}

        export PATH="/usr/lib/heimdal-servers:${PATH}"

    else
        echo "Installing MIT Kerberos packages for Debian"
        apt-get -y install \
            gss-ntlmssp \
            krb5-{user,kdc,admin-server,multidev} \
            libkrb5-dev
    fi
}

lib::setup::system_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Installing System Requirements"
    fi

    if [ -f /etc/debian_version ]; then
        lib::setup::debian_requirements

    elif [ "$(uname)" == "Darwin" ]; then
        echo "No system requirements required for macOS"

    elif [ "$(expr substr $(uname -s) 1 5)" == "MINGW" ]; then
        echo "No system requirements required for Windows"

    else
        echo "Distro not found!"
    fi

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::setup::python_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Installing Python Requirements"
    fi

    python -m pip install --upgrade pip setuptools wheel

    echo "Installing spnego"
    if [ "$(expr substr $(uname -s) 1 5)" == "MINGW" ]; then
        DIST_LINK_PATH="$( echo "${PWD}/dist" | sed -e 's/^\///' -e 's/\//\\/g' -e 's/^./\0:/' )"
    else
        DIST_LINK_PATH="${PWD}/dist"
    fi

    python -m pip install pyspnego \
        --no-index \
        --find-links "file://${DIST_LINK_PATH}" \
        --no-build-isolation \
        --no-dependencies \
        --verbose
    python -m pip install pyspnego

    echo "Installing dev dependencies"
    python -m pip install -r requirements-test.txt

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::sanity::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Sanity Checks"
    fi

    python -m isort . --check-only
    python -m pycodestyle . --verbose --show-source --statistics
    python -m mypy .

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::tests::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Tests"
    fi

    python -m pytest \
        -v \
        --junitxml junit/test-results.xml \
        --cov spnego \
        --cov-report xml \
        --cov-report term-missing

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}
