#!/bin/bash

echo "🔍 Checking Database State..."
echo "================================"
echo ""

# Check if postgres container is running
if ! docker ps | grep -q "day25-postgres"; then
    echo "❌ PostgreSQL container is not running!"
    echo "   Run: docker-compose up -d postgres"
    exit 1
fi

echo "📊 Checking users table..."
docker-compose exec -T postgres psql -U revenix -d revenix_db -c "SELECT COUNT(*) as user_count FROM users;"

echo ""
echo "👥 All users in database:"
docker-compose exec -T postgres psql -U revenix -d revenix_db -c "SELECT id, username, email, role, created_at FROM users;"

echo ""
echo "🧹 To delete all users:"
echo "   docker-compose exec postgres psql -U revenix -d revenix_db -c \"DELETE FROM users;\""
echo ""
echo "🔄 To completely reset:"
echo "   docker-compose down -v && docker-compose up --build"
