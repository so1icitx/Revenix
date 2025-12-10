#!/bin/bash
# Fresh Reset Script - Clears all data and restarts Revenix

echo "🔄 Revenix Fresh Start Script"
echo "=============================="
echo ""
echo "This will:"
echo "  1. Stop all containers"
echo "  2. Delete all databases and volumes (fresh start)"
echo "  3. Rebuild and restart everything"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 1
fi

echo ""
echo "📦 Stopping containers and removing volumes..."
sudo docker-compose down -v

echo ""
echo "🏗️  Rebuilding containers..."
sudo docker-compose build

echo ""
echo "🚀 Starting fresh system..."
sudo docker-compose up -d

echo ""
echo "⏳ Waiting for services to start (30 seconds)..."
sleep 30

echo ""
echo "✅ System reset complete!"
echo ""
echo "📋 Next steps:"
echo "  1. Open browser: http://localhost:3000"
echo "  2. Create new account (first signup becomes admin)"
echo "  3. Test the fixes!"
echo ""
echo "Checking service status..."
sudo docker-compose ps
