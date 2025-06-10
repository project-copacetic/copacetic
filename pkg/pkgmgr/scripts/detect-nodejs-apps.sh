if [ "$IGNORE_ERRORS" = "true" ]; then
    set -x
else
    set -ex
fi

locations=""

# Check common application locations first
for dir in /app /usr/src/app /opt/app /workspace / ; do
    if [ -f "$dir/package.json" ] && [ -f "$dir/package-lock.json" ]; then
        # Ensure we're not inside node_modules (safety check)
        if ! echo "$dir" | grep -q "node_modules"; then
            locations="$locations $dir"
            echo "Found Node.js app root: $dir"
        fi
    fi
done

# If no locations found in common places, do a broader search
if [ -z "$locations" ]; then
    echo "No Node.js applications found in common locations, searching more broadly..."
    # Find package.json files but exclude node_modules and only include those with package-lock.json
    for pkg_json in $(find / -name "package.json" -type f 2>/dev/null | grep -v node_modules | head -10); do
        dir=$(dirname "$pkg_json")
        if [ -f "$dir/package-lock.json" ]; then
            locations="$locations $dir"
            echo "Found Node.js app root: $dir"
        fi
    done
fi

if [ -z "$locations" ]; then
    echo "WARN: No Node.js application roots found (need both package.json and package-lock.json, excluding node_modules)"
    exit 0
fi

echo "Will patch Node.js applications in:$locations"