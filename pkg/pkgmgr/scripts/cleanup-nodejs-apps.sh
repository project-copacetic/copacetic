if [ "$IGNORE_ERRORS" = "true" ]; then
    set -x
else
    set -ex
fi

for dir in /app /usr/src/app /opt/app /workspace; do
    if [ -f "$dir/package.json" ] && [ -f "$dir/package-lock.json" ]; then
        # Safety check: ensure we're not in node_modules
        if echo "$dir" | grep -q "node_modules"; then
            echo "SKIP: Refusing to cleanup inside node_modules: $dir"
            continue
        fi
        
        cd "$dir" || continue
        echo "Cleaning up Node.js app root: $dir"
        
        # Update package-lock.json to be consistent with package.json
        npm install --package-lock-only --no-audit || true
        
        # Clean cache to reduce image size
        npm cache clean --force || true
    fi
done