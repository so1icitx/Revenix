#!/bin/bash
# Revenix Cleanup Script - Removes unused Vercel files and duplicates
# NOIT Competition Preparation

set -e  # Exit on error

echo "🧹 Revenix Cleanup Script"
echo "========================="
echo ""

# Define project root
PROJECT_ROOT="/home/so1icitx/projects/revenix"
cd "$PROJECT_ROOT"

# Create backup
echo "📦 Creating backup..."
BACKUP_FILE="$HOME/revenix-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
tar -czf "$BACKUP_FILE" \
    app/ \
    components/ \
    lib/ \
    styles/ \
    hooks/ \
    public/ \
    package.json \
    pnpm-lock.yaml \
    next.config.mjs \
    postcss.config.mjs \
    tsconfig.json \
    components.json \
    2>/dev/null || true

if [ -f "$BACKUP_FILE" ]; then
    echo "✅ Backup created: $BACKUP_FILE"
else
    echo "⚠️  No files to backup (might already be clean)"
fi

echo ""
echo "🗑️  Removing duplicate files..."
echo ""

# Count files before
FILES_BEFORE=$(find . -type f | wc -l)

# Remove duplicate Next.js directories (real ones are in dashboard/)
if [ -d "app" ] && [ -d "dashboard/app" ]; then
    echo "  Removing duplicate app/ directory..."
    rm -rf app/
fi

if [ -d "components" ] && [ -d "dashboard/components" ]; then
    echo "  Removing duplicate components/ directory..."
    rm -rf components/
fi

if [ -d "lib" ] && [ -d "dashboard/lib" ]; then
    echo "  Removing duplicate lib/ directory..."
    rm -rf lib/
fi

if [ -d "styles" ]; then
    echo "  Removing duplicate styles/ directory..."
    rm -rf styles/
fi

if [ -d "hooks" ]; then
    echo "  Removing duplicate hooks/ directory..."
    rm -rf hooks/
fi

if [ -d "public" ] && [ -d "dashboard/public" ]; then
    echo "  Removing duplicate public/ directory..."
    rm -rf public/
fi

# Remove duplicate config files
if [ -f "package.json" ] && [ -f "dashboard/package.json" ]; then
    echo "  Removing duplicate package.json..."
    rm -f package.json
fi

if [ -f "pnpm-lock.yaml" ]; then
    echo "  Removing pnpm-lock.yaml..."
    rm -f pnpm-lock.yaml
fi

if [ -f "next.config.mjs" ] && [ -f "dashboard/next.config.js" ]; then
    echo "  Removing duplicate next.config.mjs..."
    rm -f next.config.mjs
fi

if [ -f "postcss.config.mjs" ] && [ -f "dashboard/postcss.config.js" ]; then
    echo "  Removing duplicate postcss.config.mjs..."
    rm -f postcss.config.mjs
fi

if [ -f "tsconfig.json" ] && [ -f "dashboard/tsconfig.tsx" ]; then
    echo "  Removing duplicate tsconfig.json..."
    rm -f tsconfig.json
fi

if [ -f "components.json" ]; then
    echo "  Removing components.json..."
    rm -f components.json
fi

# Remove likely scratch files
if [ -f "commit" ]; then
    FILE_SIZE=$(wc -c < "commit")
    if [ "$FILE_SIZE" -lt 100 ]; then
        echo "  Removing scratch file 'commit'..."
        rm -f commit
    fi
fi

# Count files after
FILES_AFTER=$(find . -type f | wc -l)
FILES_REMOVED=$((FILES_BEFORE - FILES_AFTER))

echo ""
echo "✅ Cleanup Complete!"
echo "===================="
echo "Files removed: $FILES_REMOVED"
echo "Backup location: $BACKUP_FILE"
echo ""
echo "Next steps:"
echo "  1. Review changes: git status"
echo "  2. Test build: docker-compose build"
echo "  3. Apply critical fixes (see cleanup_and_improvements.md)"
echo ""
