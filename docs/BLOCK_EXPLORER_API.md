# Block Explorer API Documentation

This document describes the REST API endpoints specifically designed for block explorer integration with the QRDX blockchain.

## Overview

The QRDX node provides comprehensive REST API endpoints that enable block explorers to:
- Track token holdings (QRC-20, QRC-721, QRC-1155)
- Display top addresses by balance or activity
- Show recent transactions and blocks
- Display validator attestations
- Provide detailed token contract information

All endpoints support optional `pretty=true` parameter for formatted JSON output.

---

## Token Tracking Endpoints

### GET `/get_address_tokens`

**Description:** Retrieve all QRC-20, QRC-721, and QRC-1155 tokens owned by an address.

**Parameters:**
- `address` (required): The address to query
- `token_type` (optional): Filter by token type (future enhancement)
- `pretty` (optional, default: false): Return formatted JSON

**Rate Limit:** 8 requests/second

**Response:**
```json
{
  "ok": true,
  "result": {
    "address": "0x1234567890123456789012345678901234567890",
    "tokens": [
      {
        "contract_address": "0xABCD...",
        "name": "Example Token",
        "symbol": "EXT",
        "verified": true,
        "type": "QRC-20",
        "transfer_count": 42
      }
    ],
    "total_tokens": 1
  }
}
```

**Implementation Details:**
- Queries `contract_logs` table for Transfer events (topic0 = keccak256("Transfer(address,address,uint256)"))
- Matches recipient addresses in topic2
- Joins with `contract_metadata` for token details
- Calculates balance by counting transfers in/out

---

### GET `/get_token_info`

**Description:** Get detailed information about a specific token contract.

**Parameters:**
- `token_address` (required): The token contract address
- `pretty` (optional, default: false): Return formatted JSON

**Rate Limit:** 8 requests/second

**Response:**
```json
{
  "ok": true,
  "result": {
    "contract_address": "0xABCD...",
    "name": "Example Token",
    "symbol": "EXT",
    "verified": true,
    "compiler_version": "0.8.24",
    "deployer": "0x1234...",
    "deployed_at": 12345,
    "total_transfers": 1000,
    "total_holders": 250,
    "abi": "[...]"
  }
}
```

**Implementation Details:**
- Queries `contract_metadata`, `account_state`, and `contract_code` tables
- Calculates transfer count from `contract_logs`
- Counts unique holders from Transfer event recipients
- Returns ABI only for verified contracts

---

## Address Ranking Endpoints

### GET `/get_top_addresses`

**Description:** Get top addresses ranked by balance, transaction count, or token holdings.

**Parameters:**
- `limit` (optional, default: 100, max: 1000): Number of addresses to return
- `offset` (optional, default: 0): Pagination offset
- `order_by` (optional, default: "balance"): Ranking criteria
  - `balance`: Sort by total balance (sum of unspent outputs)
  - `transactions`: Sort by transaction count
  - `tokens`: Sort by number of distinct tokens held
- `pretty` (optional, default: false): Return formatted JSON

**Rate Limit:** 5 requests/minute

**Response (order_by=balance):**
```json
{
  "ok": true,
  "result": {
    "addresses": [
      {
        "address": "0x1234...",
        "balance": "1000000.000000",
        "output_count": 42
      }
    ],
    "count": 100,
    "order_by": "balance"
  }
}
```

**Response (order_by=transactions):**
```json
{
  "ok": true,
  "result": {
    "addresses": [
      {
        "address": "0x1234...",
        "transaction_count": 5000
      }
    ],
    "count": 100,
    "order_by": "transactions"
  }
}
```

**Response (order_by=tokens):**
```json
{
  "ok": true,
  "result": {
    "addresses": [
      {
        "address": "0x000...064",
        "token_count": 25,
        "transfer_count": 150
      }
    ],
    "count": 100,
    "order_by": "tokens"
  }
}
```

**Implementation Details:**
- **Balance**: Aggregates `unspent_outputs` by address
- **Transactions**: Counts occurrences in `inputs_addresses` and `outputs_addresses`
- **Tokens**: Counts distinct contract addresses in Transfer events per recipient

---

## Transaction & Block Endpoints

### GET `/get_recent_transactions`

**Description:** Get the most recent transactions across the blockchain.

**Parameters:**
- `limit` (optional, default: 50, max: 500): Number of transactions to return
- `offset` (optional, default: 0): Pagination offset
- `include_contract_txs` (optional, default: true): Include contract transactions
- `pretty` (optional, default: false): Return formatted JSON

**Rate Limit:** 10 requests/minute

**Response:**
```json
{
  "ok": true,
  "result": {
    "transactions": [
      {
        "tx_hash": "abc123...",
        "block_number": 12345,
        "timestamp": "2026-01-29T12:00:00",
        "fees": "0.001000",
        "output_count": 2,
        "type": "regular"
      },
      {
        "tx_hash": "def456...",
        "block_number": 12344,
        "timestamp": "2026-01-29T11:59:30",
        "from": "0x1234...",
        "to": "0x5678...",
        "value": "1000000000000000000",
        "gas_used": 21000,
        "status": "success",
        "type": "contract"
      }
    ],
    "count": 50
  }
}
```

**Implementation Details:**
- Queries both `transactions` (regular) and `contract_transactions` tables
- Joins with `blocks` for timestamp information
- Sorts by block number descending
- Merges and re-sorts both transaction types

---

### GET `/get_recent_blocks`

**Description:** Get the most recent blocks with validator information (for PoS blocks).

**Parameters:**
- `limit` (optional, default: 50, max: 500): Number of blocks to return
- `offset` (optional, default: 0): Pagination offset
- `include_validator_info` (optional, default: true): Include validator details
- `pretty` (optional, default: false): Return formatted JSON

**Rate Limit:** 10 requests/minute

**Response:**
```json
{
  "ok": true,
  "result": {
    "blocks": [
      {
        "block_number": 12345,
        "block_hash": "abc123...",
        "timestamp": "2026-01-29T12:00:00",
        "reward": "2.500000",
        "tx_count": 10,
        "slot": 98760,
        "epoch": 3078,
        "proposer": "0xValidator1234...",
        "attestations": 100,
        "validator": {
          "address": "0xValidator1234...",
          "stake": "32000000.000000",
          "effective_stake": "32000000.000000",
          "status": "active"
        }
      },
      {
        "block_number": 12344,
        "block_hash": "def456...",
        "timestamp": "2026-01-29T11:59:48",
        "reward": "5.000000",
        "tx_count": 5,
        "miner": "0xMiner5678..."
      }
    ],
    "count": 50
  }
}
```

**Implementation Details:**
- Queries `blocks` table ordered by ID descending
- For PoS blocks (slot != null), includes validator information
- For PoW blocks, shows miner address
- Joins with `validators` table when `include_validator_info=true`
- Counts transactions per block

---

## Attestation Endpoints

### GET `/get_attestations`

**Description:** Get validator attestations filtered by slot, epoch, validator, or block.

**Parameters:**
- `slot` (optional): Filter by slot number
- `epoch` (optional): Filter by epoch number
- `validator_address` (optional): Filter by validator address
- `block_hash` (optional): Filter by attested block hash
- `limit` (optional, default: 100, max: 1000): Number of attestations to return
- `offset` (optional, default: 0): Pagination offset
- `pretty` (optional, default: false): Return formatted JSON

**Rate Limit:** 10 requests/minute

**Response:**
```json
{
  "ok": true,
  "result": {
    "attestations": [
      {
        "id": 123456,
        "slot": 98760,
        "epoch": 3078,
        "block_hash": "abc123...",
        "validator": {
          "address": "0xValidator1234...",
          "index": 42,
          "stake": "32000000.000000",
          "effective_stake": "32000000.000000",
          "status": "active"
        },
        "checkpoint": {
          "source_epoch": 3077,
          "target_epoch": 3078
        },
        "inclusion": {
          "block_hash": "def456...",
          "slot": 98761
        },
        "created_at": "2026-01-29T12:00:00"
      }
    ],
    "count": 100,
    "filters": {
      "slot": 98760,
      "epoch": null,
      "validator": null,
      "block_hash": null
    }
  }
}
```

**Implementation Details:**
- Queries `attestations` table with flexible filtering
- Joins with `validators` table for stake and status information
- Includes checkpoint information (source/target epochs)
- Shows inclusion details (which block included the attestation)
- Sorts by slot descending, then validator index ascending

---

## Database Schema Support

These endpoints rely on the following database tables:

### Contract Tables (`schema_contracts.sql`)
- `account_state`: Ethereum-style accounts and balances
- `contract_metadata`: Token names, symbols, verification status
- `contract_code`: Bytecode and deployment info
- `contract_logs`: Event logs with indexed topics
- `contract_transactions`: Contract transaction history

### PoS Tables (`schema.sql`)
- `blocks`: Block data with PoS fields (slot, epoch, proposer)
- `validators`: Validator registry with stakes and status
- `attestations`: Validator attestations for finality
- `epochs`: Epoch metadata and finalization

### Legacy Tables
- `transactions`: Regular UTXO transactions
- `unspent_outputs`: UTXO set for balance calculations

---

## Error Handling

All endpoints return consistent error responses:

```json
{
  "ok": false,
  "error": "Error description"
}
```

Common HTTP status codes:
- `200`: Success
- `400`: Bad Request (invalid parameters)
- `403`: Forbidden (authentication required)
- `429`: Rate Limit Exceeded
- `500`: Internal Server Error

---

## Rate Limiting

All endpoints are rate-limited to prevent abuse:
- `/get_address_tokens`: 8 req/sec
- `/get_token_info`: 8 req/sec
- `/get_top_addresses`: 5 req/min
- `/get_recent_transactions`: 10 req/min
- `/get_recent_blocks`: 10 req/min
- `/get_attestations`: 10 req/min

---

## Security Considerations

1. **Input Validation**: All addresses and hashes are validated before querying
2. **SQL Injection**: All queries use parameterized statements
3. **Query Limits**: Maximum limits prevent resource exhaustion
4. **Rate Limiting**: Per-IP rate limits prevent DoS attacks

---

## Usage Examples

### Get tokens owned by an address
```bash
curl "http://localhost:3007/get_address_tokens?address=0x1234567890123456789012345678901234567890&pretty=true"
```

### Get top 10 richest addresses
```bash
curl "http://localhost:3007/get_top_addresses?limit=10&order_by=balance&pretty=true"
```

### Get recent blocks with validator info
```bash
curl "http://localhost:3007/get_recent_blocks?limit=20&include_validator_info=true&pretty=true"
```

### Get attestations for a specific epoch
```bash
curl "http://localhost:3007/get_attestations?epoch=3078&limit=100&pretty=true"
```

### Get recent transactions
```bash
curl "http://localhost:3007/get_recent_transactions?limit=50&include_contract_txs=true&pretty=true"
```

---

## Integration Notes

### For Block Explorers

1. **Initial Sync**: Use `/get_recent_blocks` and `/get_recent_transactions` to populate initial data
2. **Real-time Updates**: Poll these endpoints or use WebSocket subscriptions (if available)
3. **Address Pages**: Combine `/get_address_info` with `/get_address_tokens` for complete address view
4. **Token Pages**: Use `/get_token_info` for token details and holders
5. **Leaderboards**: Use `/get_top_addresses` with different `order_by` values
6. **PoS Dashboard**: Use `/get_attestations` and `/get_recent_blocks` for validator activity

### Performance Optimization

1. **Pagination**: Always use pagination for large datasets
2. **Caching**: Cache frequently accessed data (top addresses, token info)
3. **Indexing**: The database includes indexes on frequently queried fields
4. **Rate Limits**: Respect rate limits to avoid throttling

---

## Future Enhancements

Planned improvements:
- WebSocket subscriptions for real-time updates
- GraphQL endpoint for flexible queries
- Enhanced token balance calculations (decode Transfer event data)
- Token holder snapshots at specific block heights
- Historical balance tracking
- Advanced filtering options (date ranges, value ranges)
- CSV/JSON export for large datasets

---

## Support

For issues or questions:
- GitHub: https://github.com/The-Sycorax/denaro
- Documentation: See `/docs` directory
- API Reference: See `target-openapi.json`
