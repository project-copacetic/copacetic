if [ "$IGNORE_ERRORS" = "true" ]; then
    set -x
else
    set -ex
fi

# Only operate on detected Node.js application roots (never in node_modules)
for dir in /app /usr/src/app /opt/app /workspace; do
    if [ -f "$dir/package.json" ] && [ -f "$dir/package-lock.json" ]; then
        # Safety check: ensure we're not in node_modules
        if echo "$dir" | grep -q "node_modules"; then
            echo "SKIP: Refusing to patch inside node_modules: $dir"
            continue
        fi
        
        cd "$dir" || continue
        echo "Updating $PACKAGE_NAME in Node.js app root: $dir"
        
        # Check if package is a direct dependency
        if grep -q "\"$PACKAGE_NAME\"" package.json 2>/dev/null; then
            # Direct dependency - we can update it directly
            npm install "$SAFE_PACKAGE_NAME@$SAFE_FIXED_VERSION" --save-exact --no-audit 2>&1 | tee /tmp/npm-update-$$.log
            if [ $? -eq 0 ]; then
                echo "SUCCESS: Updated direct dependency $PACKAGE_NAME to $FIXED_VERSION in $dir"
            else
                echo "WARN: Failed to update direct dependency $PACKAGE_NAME in $dir - check /tmp/npm-update-$$.log"
                if [ "$IGNORE_ERRORS" != "true" ]; then
                    exit 1
                fi
            fi
        else
            # Transitive dependency - try npm update (less reliable but safer)
            npm update "$SAFE_PACKAGE_NAME" --no-audit 2>&1 | tee /tmp/npm-update-$$.log
            echo "Attempted to update transitive dependency $PACKAGE_NAME in $dir"
        fi
    fi
done