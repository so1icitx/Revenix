#!/bin/bash
echo "=== Day 23 Complete Verification ==="
echo ""

# Test 1: Flow Aggregation
echo "1. TESTING FLOW AGGREGATION"
echo "----------------------------"
echo "Checking for aggregated flows (flow_count > 1)..."
AGGREGATED=$(curl -s http://localhost:8000/flows | jq '[.[] | select(.flow_count > 1)] | length')
echo "✓ Aggregated flows found: $AGGREGATED"

echo "Sample aggregated flows:"
curl -s http://localhost:8000/flows | jq '.[] | select(.flow_count > 1) | {src_ip, dst_ip, flow_count, packets, bytes, last_seen}' | head -20

echo "Checking API logs for aggregation messages..."
docker logs day23-api-1 --tail 50 | grep "Processed batch" | tail -5
echo ""

# Test 2: Smart Retraining
echo "2. TESTING SMART RETRAINING"
echo "----------------------------"
echo "Checking Brain logs for retraining throttling..."
docker logs day23-brain-1 --tail 100 | grep -E "Skipping retrain|Retraining" | tail -10
echo ""

# Test 3: Flow Marking
echo "3. TESTING FLOW MARKING"
echo "----------------------------"
echo "Checking analyzed flows count..."
ANALYZED=$(curl -s http://localhost:8000/flows | jq '[.[] | select(.analyzed_at != null)] | length')
UNANALYZED=$(curl -s http://localhost:8000/flows | jq '[.[] | select(.analyzed_at == null)] | length')
TOTAL=$(curl -s http://localhost:8000/flows | jq 'length')

echo "✓ Analyzed flows: $ANALYZED"
echo "✓ Unanalyzed flows: $UNANALYZED"
echo "✓ Total flows: $TOTAL"

echo ""
echo "Sample analyzed flows with timestamps:"
curl -s http://localhost:8000/flows | jq '.[] | select(.analyzed_at != null) | {id, analyzed_at, analysis_version}' | head -10

echo ""
echo "Checking Brain logs for analysis activity..."
docker logs day23-brain-1 --tail 100 | grep -E "analyzing.*flows for threats" | tail -5

echo ""

# Test 4: Verify Global IF is trained
echo "4. TESTING GLOBAL ISOLATION FOREST"
echo "-----------------------------------"
docker logs day23-brain-1 --tail 200 | grep -E "Global IF training|is_trained=True|Baseline trained" | tail -5

echo ""

# Test 5: Check system is processing new flows
echo "5. TESTING REAL-TIME PROCESSING"
echo "--------------------------------"
echo "Recent API activity (last 20 lines):"
docker logs day23-api-1 --tail 20

echo ""
echo "Recent Brain activity (last 20 lines):"
docker logs day23-brain-1 --tail 20

echo ""
echo "=== VERIFICATION COMPLETE ==="
echo ""
echo "EXPECTED RESULTS:"
echo "1. Aggregated flows > 0"
echo "2. 'Skipping retrain' messages showing X/500 flows, Y/7.0 days"
echo "3. Analyzed flows > 0, with analyzed_at timestamps"
echo "4. 'Global IF training complete. is_trained=True' message"
echo "5. Active processing logs showing system is running"
