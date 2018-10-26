#!/usr/bin/env bash

TMPDIR=$(mktemp -d -t sft-audit-events)
VERSION=$1
OUTPUT_DIR=$PWD

# Create an archive of the repo and store it in a temp dir.
git archive --format=tar.gz --prefix "sft-audit-events-splunk/" "v$VERSION" > "$TMPDIR/sft-audit-events-$VERSION.tar.gz"

cd "$TMPDIR"
echo "$TMPDIR"

# Extract the archive
tar xzf "sft-audit-events-$VERSION.tar.gz"

cd "sft-audit-events-splunk"

# Remove all hidden files
find . -name ".*" -exec rm -rf {} \;

# Remove invalid xml
rm bin/app/node_modules/json-schema/draft-zyp-json-schema-03.xml
rm bin/app/node_modules/json-schema/draft-zyp-json-schema-04.xml
rm bin/app/node_modules/sax/examples/big-not-pretty.xml
rm bin/app/node_modules/sax/examples/not-pretty.xml
rm bin/app/node_modules/sax/examples/test.xml

# Remove splunk sdk and tests
rm -rf bin/app/node_modules/splunk-sdk/examples
rm -rf bin/app/node_modules/splunk-sdk/tests

# Remove scripts dir
rm -rf scripts

cd ..

tar czf "$OUTPUT_DIR/sft-audit-events-$VERSION.tar.gz" "sft-audit-events-splunk"
