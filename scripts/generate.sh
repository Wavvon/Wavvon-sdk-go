#!/usr/bin/env sh
# Regenerates rest/rest.gen.go from a Wavvon-docs checkout and records the
# docs commit in rest/SPEC_COMMIT.
#
#   scripts/generate.sh [docs-path] [git-ref]
#
# docs-path defaults to ../../docs (the monorepo layout), git-ref to HEAD: the
# spec is read from that commit, never the working tree. scripts/specpatch
# fixes what oapi-codegen rejects and prints each fix; a patched spec is
# recorded as <commit>+specpatch.
set -eu
cd "$(dirname "$0")/.."
docs="${1:-../../docs}"
ref="${2:-HEAD}"
oapi="github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.5.0"

commit="$(git -C "$docs" rev-parse "$ref")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git -C "$docs" show "$commit:openapi.yaml" > "$tmp/openapi.yaml"
(cd scripts/specpatch && go run . < "$tmp/openapi.yaml" > "$tmp/patched.yaml" 2> "$tmp/patches.log") || { cat "$tmp/patches.log"; exit 1; }
cat "$tmp/patches.log" >&2
[ -s "$tmp/patches.log" ] && commit="$commit+specpatch"

go run "$oapi" -config rest/oapi-codegen.yaml "$tmp/patched.yaml"
echo "$commit" > rest/SPEC_COMMIT
echo "rest/rest.gen.go generated from Wavvon-docs $commit"
