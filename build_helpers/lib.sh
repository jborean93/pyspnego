#!/bin/bash


lib::setup::debian_requirements() {
    echo "Installing Debian based pre-requisites"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update

    if [ x"$GSSAPI_PROVIDER" = "xheimdal" ]; then
        echo "Installing Heimdal packages for Debian"
        apt-get -y install \
            heimdal-{clients,dev}

    else
        echo "Installing MIT Kerberos packages for Debian"
        apt-get -y install \
            gss-ntlmssp \
            krb5-{user,multidev} \
            libkrb5-dev
    fi

    if ! command -v pwsh > /dev/null; then
        # PowerShell runs the KDC used by the Kerberos tests. The powershell
        # package in the Microsoft repository tracks the latest stable release.
        echo "Installing PowerShell from the Microsoft package repository"
        apt-get -y install \
            ca-certificates \
            curl

        source /etc/os-release
        curl -sSL \
            "https://packages.microsoft.com/config/debian/${VERSION_ID}/packages-microsoft-prod.deb" \
            -o /tmp/packages-microsoft-prod.deb
        dpkg -i /tmp/packages-microsoft-prod.deb
        rm -f /tmp/packages-microsoft-prod.deb

        apt-get update
        apt-get -y install powershell
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

    if command -v pwsh > /dev/null; then
        echo "Using PowerShell $( pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' )"
    else
        echo "PowerShell 7.6 or newer is required to run the Kerberos tests" >&2
        return 1
    fi

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::setup::python_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Installing Python Requirements"
    fi

    echo "Installing spnego"

    # Getting the version is important so that pip prioritises our local dist
    python -m pip install build
    SPNEGO_VERSION="$( python -c "import build.util; print(build.util.project_wheel_metadata('.').get('Version'))" )"

    python -m pip install pyspnego=="${SPNEGO_VERSION}" \
        --find-links dist \
        --verbose

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

    python -m ruff check .
    python -m ruff format . --check
    python -m mypy .

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::tests::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Tests"
    fi

    # The Kerberos tests need a KDC, the PowerShell script starts one and runs
    # the command given with the realm details set in the environment.
    pwsh -NoProfile -NonInteractive -File build_helpers/run-with-kdc.ps1 \
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
