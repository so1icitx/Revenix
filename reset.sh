#!/bin/bash

echo "🔥 COMPLETE RESET - Revenix AI Firewall"
echo "========================================"
echo ""
echo "This will:"
echo "  - Stop all containers"
echo "  - Delete all volumes (database, models)"
echo "  - Rebuild from scratch"
echo ""
read -p "Continue? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🛑 Stopping containers..."
    docker-compose down
    
    echo "🗑️  Removing volumes..."
    docker-compose down -v
    docker volume rm day25_postgres_data day25_brain_models 2>/dev/null || true
    docker volume prune -f
    
    echo "🧹 Cleaning up Docker system..."
    docker system prune -f
    
    echo "🔨 Rebuilding containers..."
    docker-compose build --no-cache
    
    echo "🚀 Starting fresh system..."
    docker-compose up -d
    
    echo ""
    echo "✅ RESET COMPLETE!"
    echo ""
    echo "📋 Next steps:"
    echo "  1. Clear browser storage (F12 → Application → Clear site data)"
    echo "  2. Visit http://localhost:3000"
    echo "  3. You should see the SIGNUP page"
    echo ""
    echo "📊 Check logs:"
    echo "  docker-compose logs -f"
    echo ""
else
    echo "❌ Reset cancelled"
fi
