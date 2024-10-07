#!/bin/bash

set -euox pipefail

TPL_FILE="THIRD-PARTY-LICENSES"
LICENSE_OVERRIDE_FILE="/tmp/Pygments.yaml"
REQUIREMENTS_FILE="temp_requirements.txt"

pip-compile -o "$REQUIREMENTS_FILE"
# pip-compile changes Pygments to lower case, so third_party_license_file_generator can't find it
sed -i "s/pygments/Pygments/" "$REQUIREMENTS_FILE"
# third_party_license_file_generator fails to get the license for Pygments, so we override it
echo "{Pygments: {license_name: BSD-2-Clause, license_file: https://raw.githubusercontent.com/pygments/pygments/refs/heads/master/LICENSE}}" > "$LICENSE_OVERRIDE_FILE"
python -m third_party_license_file_generator -g -r "$REQUIREMENTS_FILE" -p .venv/bin/python -l "$LICENSE_OVERRIDE_FILE" -o "$TPL_FILE"
rm "$REQUIREMENTS_FILE"
rm "$LICENSE_OVERRIDE_FILE"
# some license file cleanup
sed -i "s/^GNU GENERAL PUBLIC LICENSE/                    GNU GENERAL PUBLIC LICENSE/" "$TPL_FILE"
sed -i -e "/^Requires:/d" -e "/^Author:/d" -e '1,2d;$d' "$TPL_FILE"
