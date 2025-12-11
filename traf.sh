echo "=== HARMONY CHECK ==="
echo "1. Database Flows:"
curl -s http://localhost:8000/flows | jq 'length'

echo "2. System Health Flows:"
curl -s http://localhost:5000/system/health | jq '.total_flows_processed'

echo "3. Baseline Collection:"
docker logs day24-brain-1 --tail 50 | grep "Collected" | tail -1

echo "4. IF Training Status:"
docker logs day24-brain-1 --tail 50 | grep "IF trained status" | tail -1

echo "5. Autoencoder Status:"
curl -s http://localhost:5000/devices/profiles | jq '.[0] | {device_id, flow_count, if_trained, autoencoder_trained}'
