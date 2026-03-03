#!/bin/bash
# Update Mulberry timezone database using vzic
# Uses system tzdata to generate iCalendar VTIMEZONE .ics files
#
# This script is called during debian package build (debian/rules)
# and can also be run manually for timezone updates.

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VZIC_SOURCE_DIR="$PROJECT_ROOT/Libraries/vzic"
VZIC_BUILD_DIR="$PROJECT_ROOT/Libraries/vzic/build"
OUTPUT_DIR="$PROJECT_ROOT/Sources_Common/Timezones/zoneinfo"

echo "=== Mulberry Timezone Database Update ==="
echo "Project root: $PROJECT_ROOT"
echo "vzic source: $VZIC_SOURCE_DIR"
echo "Output directory: $OUTPUT_DIR"

# Check for required commands
for cmd in make pkg-config curl; do
    if ! command -v $cmd >/dev/null 2>&1; then
        echo "ERROR: Required command '$cmd' not found"
        echo "Install with: sudo apt install $cmd"
        exit 1
    fi
done

# Download latest tzdata source from IANA
echo "Finding latest tzdata version..."
TZDATA_LATEST=$(curl -sL https://data.iana.org/time-zones/releases/ | \
    grep -o 'tzdata202[0-9][a-z]*.tar.gz' | \
    sort -V | tail -1 | sed 's/\.tar\.gz//')

if [ -z "$TZDATA_LATEST" ]; then
    echo "ERROR: Could not determine latest tzdata version"
    exit 1
fi

TZDATA_URL="https://data.iana.org/time-zones/releases/$TZDATA_LATEST.tar.gz"
TZDATA_DIR="/tmp/tzdata-source-$$"
echo "Downloading $TZDATA_LATEST from IANA..."
mkdir -p "$TZDATA_DIR"

if ! curl -sL "$TZDATA_URL" | tar -xz -C "$TZDATA_DIR"; then
    echo "ERROR: Failed to download/extract tzdata source"
    rm -rf "$TZDATA_DIR"
    exit 1
fi

if [ ! -f "$TZDATA_DIR/africa" ]; then
    echo "ERROR: tzdata source files not found after extraction"
    rm -rf "$TZDATA_DIR"
    exit 1
fi

TZDATA_VERSION="${TZDATA_LATEST#tzdata}"
echo "Downloaded tzdata version: $TZDATA_VERSION"

# Check vzic source exists
if [ ! -d "$VZIC_SOURCE_DIR" ]; then
    echo "ERROR: vzic source not found at $VZIC_SOURCE_DIR"
    echo "Run: git submodule update --init Libraries/vzic"
    exit 1
fi

# Build vzic using Makefile
echo "Building vzic..."
cd "$VZIC_SOURCE_DIR"

make clean >/dev/null 2>&1 || true
make >/dev/null 2>&1

if [ ! -f ./vzic ]; then
    echo "ERROR: vzic build failed"
    exit 1
fi

echo "vzic built successfully"
VZIC_BINARY="$VZIC_SOURCE_DIR/vzic"

# Generate timezone files
echo "Generating timezone .ics files from system tzdata..."
TEMP_OUTPUT="/tmp/mulberry-zoneinfo-$$"
mkdir -p "$TEMP_OUTPUT"

"$VZIC_BINARY" \
    --pure \
    --olson-dir "$TZDATA_DIR" \
    --output-dir "$TEMP_OUTPUT" 2>&1 | grep -v "Modifying RRULE" || true

# Count generated files
ICS_COUNT=$(find "$TEMP_OUTPUT" -name "*.ics" | wc -l)
echo "Generated $ICS_COUNT timezone files"

if [ "$ICS_COUNT" -lt 400 ]; then
    echo "ERROR: Expected at least 400 timezone files, got $ICS_COUNT"
    rm -rf "$TEMP_OUTPUT"
    exit 1
fi

# Backup old files if they exist and we're doing an interactive update
if [ -t 1 ] && [ -d "$OUTPUT_DIR" ] && [ "$(ls -A $OUTPUT_DIR)" ]; then
    BACKUP_FILE="$PROJECT_ROOT/Sources_Common/Timezones/zoneinfo-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    echo "Backing up old timezone files to $(basename $BACKUP_FILE)..."
    tar czf "$BACKUP_FILE" -C "$PROJECT_ROOT/Sources_Common/Timezones" zoneinfo/
fi

# Replace timezone files
echo "Installing new timezone files..."
rm -rf "$OUTPUT_DIR"/*
cp -r "$TEMP_OUTPUT"/* "$OUTPUT_DIR"/

# Create version file
cat > "$OUTPUT_DIR/version.txt" <<EOF
Olson data source: tzdata$TZDATA_VERSION (IANA)
Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Tool: vzic from libical project (https://github.com/libical/vzic)
Downloaded from: $TZDATA_URL
EOF

echo "Created version file:"
cat "$OUTPUT_DIR/version.txt"

# Cleanup
rm -rf "$TEMP_OUTPUT" "$TZDATA_DIR"

# Verify installation
INSTALLED_COUNT=$(find "$OUTPUT_DIR" -name "*.ics" | wc -l)
echo "Installed $INSTALLED_COUNT timezone files to $OUTPUT_DIR"

# Spot check a few common timezones
for tz in America/New_York Europe/London Asia/Tokyo; do
    if [ ! -f "$OUTPUT_DIR/$tz.ics" ]; then
        echo "WARNING: Expected timezone file missing: $tz.ics"
    fi
done

echo "=== Timezone database update complete ==="
