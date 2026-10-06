#!/bin/bash -ex

# Run with 'GSSAPI_PROVIDER=heimdal build_helpers/run-container.sh' to run tests
# against Heimdal.

docker run \
    --rm \
    --interactive \
    --volume "$( pwd )":/tmp/build:z \
    --workdir /tmp/build \
    --env GSSAPI_PROVIDER=${GSSAPI_PROVIDER:-mit} \
    debian:12 /bin/bash -ex -c 'source /dev/stdin' << 'EOF'

source ./build_helpers/lib.sh
lib::setup::system_requirements

apt-get -y install \
    locales \
    python3 \
    python3-{dev,pip,venv}

# Debian does not allow pip to install into the system Python
python3 -m venv /tmp/venv
export PATH="/tmp/venv/bin:${PATH}"

# Ensure locale settings in test work
sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
dpkg-reconfigure --frontend=noninteractive locales

python -m pip install build
python -m build
lib::setup::python_requirements

# Ensure we don't pollute the local dir + mypy doesn't like this
rm -rf dist
rm -rf build

lib::sanity::run

export PYTEST_ADDOPTS="--color=yes"
lib::tests::run
EOF
