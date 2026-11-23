#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

mode=development
if [ "${1-}" = "--release" ]; then
    mode=release
elif [ "$#" -ne 0 ]; then
    echo "usage: $0 [--release]" >&2
    exit 2
fi

source_file=provmanager.py
output_dir=${PROVMANAGER_BUILD_DIR-build}
git_command=${GIT-git}
assignment='PROVMANAGER_VERSION = "1.0.0"'

if [ "$(grep -Fxc "$assignment" "$source_file")" -ne 1 ]; then
    echo "build refused: expected exactly one recognizable base version assignment" >&2
    exit 1
fi

git_id=$($git_command rev-parse --short HEAD)
if [ "$mode" = release ]; then
    version="1.0.0+$git_id"
else
    commit_count=$($git_command rev-list --count HEAD)
    version="1.0.0-dev.$commit_count+$git_id"
fi

mkdir -p "$output_dir"
sed "s/^PROVMANAGER_VERSION = \"1.0.0\"$/PROVMANAGER_VERSION = \"$version\"/" "$source_file" > "$output_dir/provmanager.py"
cp provmanager.cgi requirements.txt provmanager.conf.example provmanager-form-auth.conf.example provmanager-tftp-read.te.example "$output_dir/"
chmod +x "$output_dir/provmanager.cgi"
echo "Built ProvManager $version in $output_dir"
