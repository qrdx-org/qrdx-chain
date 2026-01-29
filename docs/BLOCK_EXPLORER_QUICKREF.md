# Block Explorer API - Quick Reference

## Endpoints Summary

| Endpoint | Purpose | Rate Limit |
|----------|---------|------------|
| `/get_address_tokens` | Get tokens owned by address | 8/sec |
| `/get_token_info` | Get token contract details | 8/sec |
| `/get_top_addresses` | Get ranked addresses (balance/activity) | 5/min |
| `/get_recent_transactions` | Get recent transactions | 10/min |
| `/get_recent_blocks` | Get recent blocks with validators | 10/min |
| `/get_attestations` | Get PoS attestations | 10/min |

## Quick Examples

### Check what tokens an address owns
```bash
GET /get_address_tokens?address=0x1234...&pretty=true
```

### Get top 100 richest addresses
```bash
GET /get_top_addresses?limit=100&order_by=balance&pretty=true
```

### Get most active addresses
```bash
GET /get_top_addresses?limit=100&order_by=transactions&pretty=true
```

### Get addresses with most tokens
```bash
GET /get_top_addresses?limit=100&order_by=tokens&pretty=true
```

### Get recent blocks with validator info
```bash
GET /get_recent_blocks?limit=50&include_validator_info=true&pretty=true
```

### Get recent transactions (including contract calls)
```bash
GET /get_recent_transactions?limit=100&include_contract_txs=true&pretty=true
```

### Get attestations for an epoch
```bash
GET /get_attestations?epoch=3078&limit=100&pretty=true
```

### Get attestations by validator
```bash
GET /get_attestations?validator_address=0xValidator...&limit=100&pretty=true
```

### Get token information
```bash
GET /get_token_info?token_address=0xToken...&pretty=true
```

## Response Format

All endpoints return:
```json
{
  "ok": true,
  "result": { /* endpoint-specific data */ }
}
```

Or on error:
```json
{
  "ok": false,
  "error": "Error message"
}
```

## Common Parameters

- `pretty` (bool): Format JSON output
- `limit` (int): Pagination limit
- `offset` (int): Pagination offset

## Database Tables Used

### Token Tracking
- `contract_logs` - Event logs (Transfer events)
- `contract_metadata` - Token names, symbols
- `account_state` - Account balances

### Address Rankings
- `unspent_outputs` - UTXO balances
- `transactions` - Transaction history
- `contract_logs` - Token transfers

### PoS/Validators
- `blocks` - Block data with PoS fields
- `validators` - Validator registry
- `attestations` - Attestation records
- `epochs` - Epoch metadata

## Implementation Files

- **API Endpoints**: `/workspaces/qrdx-chain-denaro/qrdx/node/main.py` (lines ~3255-3700)
- **Database Schema**: 
  - `/workspaces/qrdx-chain-denaro/qrdx/schema.sql` (PoS tables)
  - `/workspaces/qrdx-chain-denaro/qrdx/schema_contracts.sql` (Contract tables)
- **OpenAPI Spec**: `/workspaces/qrdx-chain-denaro/target-openapi.json`
- **Documentation**: `/workspaces/qrdx-chain-denaro/docs/BLOCK_EXPLORER_API.md`

## Key Features

✅ **Token Tracking** - QRC-20, QRC-721, QRC-1155 support via Transfer events
✅ **Address Rankings** - By balance, transaction count, or token holdings
✅ **Recent Activity** - Latest transactions and blocks
✅ **PoS Support** - Validator info and attestations
✅ **Pagination** - All endpoints support limit/offset
✅ **Rate Limiting** - Prevents abuse
✅ **Input Validation** - Secure parameter checking
✅ **Pretty Printing** - Optional formatted JSON

## Token Detection Method

Tokens are detected by monitoring Transfer events in `contract_logs`:
- **Event Signature**: `Transfer(address,address,uint256)`
- **Topic0**: `0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef`
- **Topic1**: From address (sender)
- **Topic2**: To address (recipient)
- **Data**: Transfer amount (for future balance calculation)

The system tracks which tokens an address has received transfers from, indicating ownership.

## Performance Notes

- All queries use database indexes
- Pagination prevents large result sets
- Rate limiting protects server resources
- Optional validator info reduces query complexity
- Contract transaction inclusion is toggleable

## Testing

Test locally:
```bash
# Start node
./run_node.py

# Test endpoints
curl "http://localhost:3007/get_recent_blocks?limit=10&pretty=true"
curl "http://localhost:3007/get_top_addresses?limit=10&order_by=balance&pretty=true"
curl "http://localhost:3007/get_attestations?epoch=1&pretty=true"
```

## Next Steps

To enhance token tracking:
1. Decode Transfer event `data` field for exact balances
2. Add token holder snapshots at block heights
3. Track token price history
4. Add token metadata cache
5. Implement token transfer history per address
