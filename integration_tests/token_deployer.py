"""
Token Deployer — Deploy and operate qRC20 tokens on the testnet.

Since the QRDX node keeps the qRC20 registry in-memory (QRC20Registry),
and the node doesn't yet expose a deploy endpoint, this module:

  1. Creates QRC20Token instances via the real qRC20 class
  2. Persists them to SQLite via TokenPersistence
  3. Interacts with the in-memory registry when running in-process
  4. Tests transfer/approve/transferFrom flows using real PQ signatures

For the integration testnet we operate tokens both via:
  - Direct Python calls (same process) for deployment/state
  - REST API calls via /get_address_tokens for verification

No stubs — real QRC20Token objects with real PQ signature verification.
"""

import asyncio
import hashlib
import logging
import time
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from qrdx.constants import QRC20_DEFAULT_DECIMALS, QRC20_MAX_SUPPLY
from qrdx.tokens.qrc20 import QRC20Token, QRC20Registry, QRC20Error
from qrdx.tokens.persistence import TokenPersistence
from integration_tests.rpc_client import NodeRPCClient

logger = logging.getLogger(__name__)


# Standard testnet token definitions
TESTNET_TOKENS = [
    {
        "name": "Quantum Ether",
        "symbol": "qETH",
        "decimals": 18,
        "initial_supply": Decimal("1000000"),
        "description": "Wrapped ETH bridged to QRDX",
    },
    {
        "name": "Quantum USD Coin",
        "symbol": "qUSDC",
        "decimals": 6,
        "initial_supply": Decimal("10000000"),
        "description": "Wrapped USDC bridged to QRDX",
    },
    {
        "name": "Quantum Bitcoin",
        "symbol": "qBTC",
        "decimals": 8,
        "initial_supply": Decimal("21000"),
        "description": "Wrapped BTC bridged to QRDX",
    },
    {
        "name": "Test Governance Token",
        "symbol": "GOV",
        "decimals": 18,
        "initial_supply": Decimal("100000000"),
        "description": "Governance token for testnet voting",
    },
]


class TokenDeployer:
    """
    Deploy and manage qRC20 tokens on the testnet.

    Usage:
        deployer = TokenDeployer(db_path="testnet/databases/node0.db")
        await deployer.initialize()

        token = await deployer.deploy_token(
            name="Quantum Ether",
            symbol="qETH",
            decimals=18,
            initial_supply=Decimal("1000000"),
            deployer_address="DKxyz...",
        )

        await deployer.transfer(
            symbol="qETH",
            sender="DKxyz...",
            recipient="DLabc...",
            amount=Decimal("100"),
            sign_fn=my_pq_sign_function,
        )
    """

    def __init__(self, db_path: str, node_url: Optional[str] = None):
        self.db_path = db_path
        self.node_url = node_url
        self._persistence: Optional[TokenPersistence] = None
        self._registry = QRC20Registry()
        self._client: Optional[NodeRPCClient] = None
        self._db: Optional[aiosqlite.Connection] = None

    async def initialize(self) -> None:
        """Initialize persistence layer and optionally connect to node."""
        import aiosqlite as _aiosqlite
        self._db = await _aiosqlite.connect(self.db_path)
        self._db.row_factory = _aiosqlite.Row
        self._persistence = TokenPersistence(self._db)
        await self._persistence.initialize()
        logger.info("Token deployer initialized (db=%s)", self.db_path)

        if self.node_url:
            self._client = NodeRPCClient(self.node_url)
            await self._client.__aenter__()

    async def close(self) -> None:
        """Clean up resources."""
        if self._client:
            await self._client.__aexit__(None, None, None)
        if self._db:
            await self._db.close()

    async def __aenter__(self):
        await self.initialize()
        return self

    async def __aexit__(self, *exc):
        await self.close()

    # ─────────── Deployment ───────────

    async def deploy_token(
        self,
        name: str,
        symbol: str,
        decimals: int = QRC20_DEFAULT_DECIMALS,
        initial_supply: Decimal = Decimal("0"),
        deployer_address: str = "",
        post_doomsday_trade: bool = True,
        source_chain_id: Optional[int] = None,
        source_token_address: Optional[str] = None,
        verify_signature_fn=None,
    ) -> QRC20Token:
        """
        Deploy a new qRC20 token.

        Creates the in-memory QRC20Token, registers it in the QRC20Registry,
        and persists the state to SQLite.
        """
        logger.info("Deploying token: %s (%s), supply=%s, deployer=%s",
                     symbol, name, initial_supply, deployer_address[:20] if deployer_address else "N/A")

        # Create the real token object
        token = QRC20Token(
            name=name,
            symbol=symbol,
            decimals=decimals,
            total_supply=initial_supply,
            deployer=deployer_address,
            post_doomsday_trade=post_doomsday_trade,
            source_chain_id=source_chain_id,
            source_token_address=source_token_address,
            verify_signature_fn=verify_signature_fn,
        )

        # Register in in-memory registry
        self._registry.deploy(token)

        # Generate a deterministic token address from symbol
        token_address = self._generate_token_address(symbol)

        # Persist to database
        await self._persistence.register_token(
            token_address=token_address,
            name=name,
            symbol=symbol,
            decimals=decimals,
            total_supply=initial_supply,
            owner_address=deployer_address,
        )

        # If there's initial supply, credit deployer

        logger.info("  ✓ Token deployed: %s at %s", symbol, token_address)
        return token

    async def deploy_standard_tokens(
        self,
        deployer_address: str,
        verify_signature_fn=None,
    ) -> Dict[str, QRC20Token]:
        """Deploy all standard testnet tokens."""
        tokens = {}
        for spec in TESTNET_TOKENS:
            token = await self.deploy_token(
                name=spec["name"],
                symbol=spec["symbol"],
                decimals=spec["decimals"],
                initial_supply=spec["initial_supply"],
                deployer_address=deployer_address,
                verify_signature_fn=verify_signature_fn,
            )
            tokens[spec["symbol"]] = token
        return tokens

    # ─────────── Transfer Operations ───────────

    async def transfer(
        self,
        symbol: str,
        sender: str,
        recipient: str,
        amount: Decimal,
        sign_fn=None,
    ) -> Dict[str, Any]:
        """
        Transfer tokens between addresses.

        Uses both in-memory QRC20Token.transfer() and persistence layer.
        """
        logger.debug("Token transfer: %s %s from %s to %s", amount, symbol, sender[:16], recipient[:16])

        token = self._registry.get_or_raise(symbol)
        token_address = self._generate_token_address(symbol)

        # Generate signature if sign_fn provided
        signature = b""
        if sign_fn:
            message = f"transfer:{symbol}:{sender}:{recipient}:{amount}".encode()
            signature = await sign_fn(sender, message)

        # Execute in-memory transfer (with PQ verification if configured)
        proof_hash = hashlib.sha256(
            f"{sender}:{recipient}:{amount}:{time.time()}".encode()
        ).hexdigest()

        # Call the real QRC20Token transfer
        event = await token.transfer(
            sender=sender,
            recipient=recipient,
            amount=amount,
            signature=signature,
        )

        # Persist to database
        await self._persistence.transfer(
            token_address=token_address,
            from_address=sender,
            to_address=recipient,
            amount=amount,
        )

        result = {
            "ok": True,
            "symbol": symbol,
            "from": sender,
            "to": recipient,
            "amount": str(amount),
            "proof_hash": proof_hash,
        }
        logger.debug("  ✓ Transfer complete: %s", result)
        return result

    async def approve(
        self,
        symbol: str,
        owner: str,
        spender: str,
        amount: Decimal,
        sign_fn=None,
    ) -> Dict[str, Any]:
        """Set approval for spender to use owner's tokens."""
        logger.debug("Token approve: %s %s, owner=%s, spender=%s", amount, symbol, owner[:16], spender[:16])

        token = self._registry.get_or_raise(symbol)
        token_address = self._generate_token_address(symbol)

        signature = b""
        if sign_fn:
            message = f"approve:{symbol}:{owner}:{spender}:{amount}".encode()
            signature = await sign_fn(owner, message)

        event = await token.approve(
            owner=owner,
            spender=spender,
            amount=amount,
            signature=signature,
        )

        await self._persistence.approve(
            token_address=token_address,
            owner=owner,
            spender=spender,
            amount=str(amount),
        )

        return {"ok": True, "symbol": symbol, "owner": owner, "spender": spender, "amount": str(amount)}

    async def transfer_from(
        self,
        symbol: str,
        spender: str,
        sender: str,
        recipient: str,
        amount: Decimal,
        sign_fn=None,
    ) -> Dict[str, Any]:
        """Transfer tokens using allowance (spender acts on behalf of sender)."""
        logger.debug("Token transferFrom: %s %s, spender=%s, from=%s, to=%s",
                     amount, symbol, spender[:16], sender[:16], recipient[:16])

        token = self._registry.get_or_raise(symbol)
        token_address = self._generate_token_address(symbol)

        signature = b""
        if sign_fn:
            message = f"transferFrom:{symbol}:{spender}:{sender}:{recipient}:{amount}".encode()
            signature = await sign_fn(spender, message)

        proof_hash = hashlib.sha256(
            f"{spender}:{sender}:{recipient}:{amount}:{time.time()}".encode()
        ).hexdigest()

        event = await token.transfer_from(
            spender=spender,
            sender=sender,
            recipient=recipient,
            amount=amount,
            signature=signature,
        )

        # Persist transfer
        await self._persistence.transfer_from(
            token_address=token_address,
            spender=spender,
            from_address=sender,
            to_address=recipient,
            amount=amount,
        )

        return {"ok": True, "symbol": symbol, "from": sender, "to": recipient, "amount": str(amount)}

    # ─────────── Query ───────────

    async def get_balance(self, symbol: str, address: str) -> Decimal:
        """Get token balance from in-memory state."""
        token = self._registry.get_or_raise(symbol)
        return token.balance_of(address)

    async def get_persisted_balance(self, symbol: str, address: str) -> Decimal:
        """Get token balance from persistence layer."""
        token_address = self._generate_token_address(symbol)
        return await self._persistence.get_balance(token_address, address)

    async def verify_consistency(self, symbol: str, address: str) -> bool:
        """Verify in-memory balance matches persisted balance."""
        memory_bal = await self.get_balance(symbol, address)
        db_bal = await self.get_persisted_balance(symbol, address)
        if memory_bal != db_bal:
            logger.warning("Balance mismatch for %s/%s: memory=%s, db=%s",
                           symbol, address[:16], memory_bal, db_bal)
            return False
        return True

    def list_tokens(self) -> List[str]:
        """List all deployed token symbols."""
        return self._registry.list_tokens()

    def get_token(self, symbol: str) -> QRC20Token:
        """Get a token object by symbol."""
        return self._registry.get_or_raise(symbol)

    # ─────────── Helpers ───────────

    @staticmethod
    def _generate_token_address(symbol: str) -> str:
        """Generate a deterministic token address from symbol."""
        raw = hashlib.blake2b(f"qrc20:{symbol}".encode(), digest_size=20).hexdigest()
        return f"0xT{raw}"

    async def get_deployment_summary(self) -> Dict[str, Any]:
        """Get a summary of all deployed tokens."""
        summary = {}
        for symbol in self._registry.list_tokens():
            token = self._registry.get(symbol)
            summary[symbol] = {
                "name": token.name,
                "symbol": token.symbol,
                "decimals": token.decimals,
                "total_supply": str(token.total_supply),
                "deployer": token.deployer,
                "address": self._generate_token_address(symbol),
            }
        return summary
