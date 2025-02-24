FROM python:3.12-bookworm

# Install uv. Official uv Docker image lacks 32bit ARM version
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates
ADD https://astral.sh/uv/install.sh /uv-installer.sh
RUN sh /uv-installer.sh && rm /uv-installer.sh
ENV PATH="/root/.local/bin/:$PATH"

# create the entrypoint script, /src and /build directories
RUN mkdir /src/ /build/ && \
    touch /entrypoint.sh && \
    chmod +x /entrypoint.sh && \
    cat > /entrypoint.sh <<'EOF'
#!/bin/bash

set -e

if [ -z "$( ls -A)" ]; then
   echo 'mount the packet-sender directory to /src/ e.g. -v "$(pwd):/src/"'
   exit 1
fi
if [ ! -f pyproject.toml ]; then
    echo "pyproject.toml not found! Wrong directory mounted?"
    exit 1
fi

cp -r src /build/
cp pyproject.toml /build/
cd /build/

uv venv --python 3.12
. .venv/bin/activate
uv pip compile -o requirements.txt --extra build pyproject.toml
uv pip install --requirement requirements.txt

pyinstaller --clean --optimize 2 -s -n packet-sender src/packet_sender/__main__.py

cd dist
output="/src/packet-sender-$(uname -m).tar.gz"
tar -czvf "$output" packet-sender
chown -R --reference=/src/. "$output"

echo -e "\nDone. Created $output"
EOF

WORKDIR /src/
ENTRYPOINT ["/entrypoint.sh"]