#!/usr/bin/env python3
"""
QRDX Wallet CLI

Command-line interface for managing QRDX wallets.

Supports both:
- Traditional wallets (secp256k1, Ethereum-compatible)
- Post-Quantum wallets (Dilithium3, quantum-resistant)

Usage:
    qrdx-wallet create [--type TYPE] [--name NAME] [--output FILE]
    qrdx-wallet info <wallet_file>
    qrdx-wallet balance <wallet_file>
    qrdx-wallet send <wallet_file> <to_address> <amount>
    qrdx-wallet export <wallet_file> [--format FORMAT]
    qrdx-wallet import <private_key> [--type TYPE] [--output FILE]
    qrdx-wallet sign <wallet_file> <message>
    qrdx-wallet verify <address> <message> <signature>
    qrdx-wallet perp …   (perpetual futures: markets, book, account, deposit, order, …)
    qrdx-wallet token …  (native tokens: list, info, balance, deploy, mint, transfer, approve, …)
    qrdx-wallet nft …    (native NFTs: collections, create, mint, transfer, approve, burn, …)
    qrdx-wallet spot …   (spot: pools, quote, swap, liquidity, order books)
"""

import sys
import os
import json
import getpass
from pathlib import Path
from typing import Optional

try:
    import click
except ImportError:
    print("Error: click is required. Install with: pip install click")
    sys.exit(1)


# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from qrdx.wallet_v2 import (
    WalletType,
    TraditionalWallet,
    PQWallet,
    UnifiedWallet,
    load_wallet,
    create_wallet,
    WalletError,
    WalletNotFoundError,
    WalletDecryptionError,
)
from qrdx.crypto import is_pq_address, is_valid_address


# Default wallet directory
DEFAULT_WALLET_DIR = Path.home() / ".qrdx" / "wallets"


def get_password(confirm: bool = False, prompt: str = "Password: ") -> str:
    """Get password from user securely."""
    password = getpass.getpass(prompt)
    
    if confirm:
        confirm_pass = getpass.getpass("Confirm password: ")
        if password != confirm_pass:
            raise click.ClickException("Passwords do not match")
    
    if len(password) < 8:
        raise click.ClickException("Password must be at least 8 characters")
    
    return password


def format_address(address: str, short: bool = False) -> str:
    """Format address for display."""
    if short:
        return f"{address[:10]}...{address[-8:]}"
    return address


@click.group()
@click.version_option(version="2.0.0", prog_name="qrdx-wallet")
def cli():
    """QRDX Wallet Command Line Interface
    
    Manage traditional (secp256k1) and post-quantum (Dilithium) wallets.
    """
    pass


@cli.command("create")
@click.option(
    "--type", "-t",
    "wallet_type",
    type=click.Choice(["traditional", "pq", "unified"]),
    default="traditional",
    help="Wallet type: traditional (secp256k1), pq (Dilithium), or unified (both)"
)
@click.option(
    "--name", "-n",
    default="My Wallet",
    help="Wallet name"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path (default: ~/.qrdx/wallets/<address>.json)"
)
@click.option(
    "--no-password",
    is_flag=True,
    help="Create without password (NOT RECOMMENDED)"
)
def create_wallet_cmd(wallet_type: str, name: str, output: Optional[str], no_password: bool):
    """Create a new wallet.
    
    Examples:
    
        qrdx-wallet create --type traditional
        
        qrdx-wallet create --type pq --name "Quantum Safe"
        
        qrdx-wallet create --type unified --output my_wallet.json
    """
    # Map string to WalletType
    type_map = {
        "traditional": WalletType.TRADITIONAL,
        "pq": WalletType.POST_QUANTUM,
        "unified": WalletType.UNIFIED,
    }
    wtype = type_map[wallet_type]
    
    click.echo(f"Creating {wallet_type} wallet...")
    
    # Generate wallet
    try:
        wallet = create_wallet(wtype, name)
    except Exception as e:
        raise click.ClickException(f"Failed to create wallet: {e}")
    
    # Get password
    if no_password:
        click.echo(click.style("WARNING: No password set. Wallet is NOT secure!", fg="red"))
        password = ""
    else:
        password = get_password(confirm=True)
    
    # Determine output path
    if output:
        wallet_path = Path(output)
    else:
        DEFAULT_WALLET_DIR.mkdir(parents=True, exist_ok=True)
        if isinstance(wallet, UnifiedWallet):
            addr = wallet.primary_address[:10]
        else:
            addr = wallet.address[:10]
        wallet_path = DEFAULT_WALLET_DIR / f"{addr}.json"
    
    # Save wallet
    try:
        if isinstance(wallet, UnifiedWallet):
            wallet.save(wallet_path, password)
        else:
            wallet.save(wallet_path, password)
        
        click.echo(click.style("✓ Wallet created successfully!", fg="green"))
        click.echo()
        
        # Display info
        if isinstance(wallet, UnifiedWallet):
            if wallet.traditional:
                click.echo(f"Traditional Address: {wallet.traditional.address}")
            if wallet.pq:
                click.echo(f"PQ Address:          {wallet.pq.address}")
        else:
            click.echo(f"Address: {wallet.address}")
        
        click.echo(f"Saved to: {wallet_path}")
        
        # Security reminder
        click.echo()
        click.echo(click.style("IMPORTANT: Back up your wallet file and remember your password!", fg="yellow"))
        
    except Exception as e:
        raise click.ClickException(f"Failed to save wallet: {e}")


@cli.command("info")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.option("--show-private", is_flag=True, help="Show private key (DANGEROUS)")
def info_cmd(wallet_file: str, show_private: bool):
    """Display wallet information.
    
    Examples:
    
        qrdx-wallet info ~/.qrdx/wallets/0x123...json
    """
    wallet_path = Path(wallet_file)
    
    password = get_password(prompt="Enter wallet password: ")
    
    try:
        wallet = load_wallet(wallet_path, password)
    except WalletDecryptionError:
        raise click.ClickException("Invalid password")
    except Exception as e:
        raise click.ClickException(f"Failed to load wallet: {e}")
    
    click.echo()
    click.echo(click.style("═══════════════════════════════════════", fg="cyan"))
    click.echo(click.style("         QRDX Wallet Information        ", fg="cyan", bold=True))
    click.echo(click.style("═══════════════════════════════════════", fg="cyan"))
    click.echo()
    
    if isinstance(wallet, UnifiedWallet):
        click.echo(f"Type: Unified (Traditional + Post-Quantum)")
        click.echo()
        
        if wallet.traditional:
            click.echo(click.style("Traditional (secp256k1):", fg="green"))
            click.echo(f"  Address: {wallet.traditional.address}")
            click.echo(f"  Public Key: {wallet.traditional.public_key_hex[:32]}...")
            if show_private:
                click.echo(click.style(f"  Private Key: {wallet.traditional.private_key_hex}", fg="red"))
            click.echo()
        
        if wallet.pq:
            click.echo(click.style("Post-Quantum (Dilithium3):", fg="blue"))
            click.echo(f"  Address: {wallet.pq.address}")
            click.echo(f"  Fingerprint: {wallet.pq.public_key_fingerprint}")
            if show_private:
                click.echo(click.style(f"  Private Key: {wallet.pq._private_key.to_hex()[:64]}...", fg="red"))
    
    elif isinstance(wallet, PQWallet):
        click.echo(f"Type: Post-Quantum (Dilithium3)")
        click.echo(f"Address: {wallet.address}")
        click.echo(f"Fingerprint: {wallet.public_key_fingerprint}")
        if show_private:
            click.echo(click.style(f"Private Key: {wallet._private_key.to_hex()[:64]}...", fg="red"))
    
    else:
        click.echo(f"Type: Traditional (secp256k1)")
        click.echo(f"Address: {wallet.address}")
        click.echo(f"Public Key: {wallet.public_key_hex}")
        if show_private:
            click.echo(click.style(f"Private Key: {wallet.private_key_hex}", fg="red"))
    
    click.echo()
    
    if wallet.metadata:
        click.echo(f"Name: {wallet.metadata.name}")
        click.echo(f"Created: {wallet.metadata.created_at}")
    
    if show_private:
        click.echo()
        click.echo(click.style("⚠️  NEVER share your private key with anyone!", fg="red", bold=True))


@cli.command("send")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("to_address")
@click.argument("amount", type=float)
@click.option("--node", "-n", default="http://localhost:3007", help="Node RPC URL")
@click.option("--fee", "-f", type=float, default=0.01, help="Transaction fee in QRDX")
@click.option(
    "--from-system-wallet",
    type=str,
    help="Send from system wallet address (requires master controller wallet)"
)
@click.option("--wait", "-w", is_flag=True, help="Wait for confirmation")
def send_cmd(wallet_file: str, to_address: str, amount: float, node: str, fee: float, from_system_wallet: Optional[str], wait: bool):
    """Send QRDX to an address.
    
    Examples:
    
        qrdx-wallet send wallet.json 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb 10.5
        
        qrdx-wallet send master.json 0x123... 100 --from-system-wallet 0x...0003 --wait
        
        qrdx-wallet send wallet.json 0xPQ... 50 --fee 0.02
    """
    from decimal import Decimal
    
    wallet_path = Path(wallet_file)
    password = get_password(prompt="Enter wallet password: ")
    
    try:
        wallet = load_wallet(wallet_path, password)
    except WalletDecryptionError:
        raise click.ClickException("Invalid password")
    except Exception as e:
        raise click.ClickException(f"Failed to load wallet: {e}")
    
    # Validate destination address
    if not is_valid_address(to_address):
        raise click.ClickException(f"Invalid destination address: {to_address}")
    
    # Determine sender
    if from_system_wallet:
        # System wallet transaction - requires master controller
        if not isinstance(wallet, PQWallet):
            raise click.ClickException("System wallet transactions require a PQ master controller wallet")
        
        # The SIGNER is the controller — that is whose nonce is consumed and whose
        # balance pays the gas. The system wallet is the delegated VALUE source, carried
        # separately in the transaction's `on_behalf_of` field.
        sender_address = wallet.address
        controller_address = wallet.address

        click.echo()
        click.echo(click.style("System Wallet Transaction", fg="cyan", bold=True))
        click.echo(f"Value from:     {from_system_wallet}")
        click.echo(f"Signed by:      {controller_address}  (pays gas, consumes nonce)")
    else:
        # Regular transaction
        if isinstance(wallet, UnifiedWallet):
            # Use traditional wallet for regular transactions
            sender = wallet.traditional if wallet.traditional else wallet.pq
            sender_address = sender.address
        else:
            sender = wallet
            sender_address = wallet.address
        
        click.echo()
        click.echo(click.style("Transaction", fg="cyan", bold=True))
        click.echo(f"From:  {sender_address}")
    
    click.echo(f"To:    {to_address}")
    click.echo(f"Amount: {amount} QRDX")
    click.echo(f"Fee:    {fee} QRDX")
    click.echo()
    
    if not click.confirm("Send transaction?"):
        click.echo("Cancelled.")
        return
    
    # ── Build and send ───────────────────────────────────────────────────────
    #
    # Transfers go through the account/EVM path (eth_sendRawTransaction) — the
    # unified ledger. The legacy UTXO path this command used to build against is
    # empty from genesis onward, so it could only ever fail with "No UTXOs found".
    #
    # Two signing envelopes, one destination ledger:
    #   * traditional (secp256k1) wallet → legacy EIP-155 transaction
    #   * post-quantum (Dilithium) wallet → type-0x51 PQ transaction
    #
    # Either can pay either kind of address, because `to` is the recipient's
    # canonical 20-byte ACCOUNT ID — which a 0xPQ address resolves to by
    # derivation. That is what makes 0x → 0xPQ and 0xPQ → 0x transfers possible.
    try:
        import httpx
        from decimal import Decimal as _D

        from ..crypto.account_id import to_account_id

        def _rpc(method, params, timeout=30.0):
            resp = httpx.post(f"{node}/rpc",
                              json={"jsonrpc": "2.0", "method": method,
                                    "params": params, "id": 1}, timeout=timeout)
            if resp.status_code != 200:
                raise click.ClickException(f"{method} failed (HTTP {resp.status_code})")
            body = resp.json()
            if "error" in body and body["error"]:
                msg = body["error"].get("message", str(body["error"]))
                raise click.ClickException(f"{method} failed: {msg}")
            return body.get("result")

        # The recipient's ledger key. Accepts 0x, 0xPQ, 0xPQMS and legacy forms.
        # Note the NONCE below is the signer's, not the system wallet's: a delegated
        # spend consumes the controller's nonce, because the controller submits and pays.
        try:
            to_account = to_account_id(to_address)
        except ValueError as e:
            raise click.ClickException(f"Cannot resolve destination address: {e}")
        if to_account != to_address.lower():
            click.echo(f"Resolved {to_address[:24]}... → account {to_account}")

        value_wei = int(_D(str(amount)) * _D(10 ** 18))

        # Nonce and chain id from the node, so the transaction is replay-bound.
        nonce = int(_rpc("eth_getTransactionCount", [sender_address, "pending"]) or "0x0", 16)
        try:
            chain_id = int(_rpc("eth_chainId", []) or "0x0", 16)
        except click.ClickException:
            chain_id = 0

        # `fee` is a gas PRICE in QRDX per gas unit on this path; derive wei/gas.
        gas_price_wei = max(1, int(_D(str(fee)) * _D(10 ** 18) // _D(21000)))

        # A system-wallet send is a DELEGATED spend: the controller signs, the value
        # leaves the system wallet, and gas + nonce stay with the controller. The node
        # authorises the controller relationship against its genesis-registered
        # system_wallets table before anything moves.
        on_behalf_of = None
        if from_system_wallet:
            if not isinstance(wallet, PQWallet):
                raise click.ClickException(
                    "System-wallet sends must be signed by the controller, which is a "
                    "post-quantum (0xPQ) or multisig wallet.")
            try:
                on_behalf_of = bytes.fromhex(to_account_id(from_system_wallet)[2:])
            except ValueError as e:
                raise click.ClickException(f"Invalid system wallet address: {e}")
            click.echo(f"Delegated spend from system wallet {from_system_wallet[:24]}...")
            click.echo(f"  authorised by controller {wallet.address[:24]}...")

        click.echo("Signing transaction...")
        if isinstance(wallet, PQWallet):
            from ..transactions.pq_tx import PQTransaction, intrinsic_gas_pq
            from ..crypto.pq.dilithium import PUBLIC_KEY_SIZE, SIGNATURE_SIZE

            # A PQ transaction must supply its intrinsic floor, which prices the
            # ~5.3KB Dilithium key + signature it carries.
            gas_limit = intrinsic_gas_pq(b"", b"\x00" * PUBLIC_KEY_SIZE,
                                        b"\x00" * SIGNATURE_SIZE) + 30_000
            tx = PQTransaction(
                chain_id=chain_id,
                nonce=nonce,
                gas_price=gas_price_wei,
                gas_limit=gas_limit,
                to=bytes.fromhex(to_account[2:]),
                value=value_wei,
                data=b"",
                on_behalf_of=on_behalf_of,
            )
            tx.sign(wallet._private_key)
            raw_hex = "0x" + tx.encode().hex()
            click.echo(f"  Post-quantum (ML-DSA-65) signature, {len(raw_hex) // 2} bytes")
        else:
            from eth_account import Account as EthAccount

            signer = wallet.traditional if isinstance(wallet, UnifiedWallet) and wallet.traditional else wallet
            key_hex = signer.private_key_hex
            signed = EthAccount.sign_transaction(
                {"nonce": nonce, "gasPrice": gas_price_wei, "gas": 21000,
                 "to": to_account, "value": value_wei, "data": b"",
                 "chainId": chain_id},
                key_hex if key_hex.startswith("0x") else "0x" + key_hex,
            )
            raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
            raw_hex = "0x" + bytes(raw).hex()
            click.echo("  secp256k1 (EIP-155) signature")

        click.echo("Broadcasting transaction...")
        tx_hash_result = _rpc("eth_sendRawTransaction", [raw_hex])

        click.echo()
        click.echo(click.style("✓ Transaction submitted!", fg="green", bold=True))
        click.echo(f"TX Hash: {tx_hash_result}")
        click.echo("Balances change when a proposer includes it in a block.")

        if wait:
            click.echo()
            click.echo("Waiting for inclusion...")
            import time
            for i in range(30):
                time.sleep(2)
                try:
                    receipt = _rpc("eth_getTransactionReceipt", [tx_hash_result], timeout=10.0)
                except click.ClickException:
                    receipt = None
                if receipt:
                    ok = str(receipt.get("status", "0x1")).rstrip("0") != "0x"
                    click.echo(click.style(
                        "✓ Included!" if ok else "✗ Included but reverted",
                        fg="green" if ok else "red", bold=True))
                    click.echo(f"Block: {receipt.get('blockNumber')}  "
                               f"Gas used: {receipt.get('gasUsed')}")
                    break
                click.echo(f"  Waiting... ({i * 2}s)")
            else:
                click.echo(click.style("⚠ Timeout waiting for inclusion", fg="yellow"))
                click.echo("Transaction may still be pending in the mempool.")

    except click.ClickException:
        raise
    except ImportError as e:
        raise click.ClickException(f"Missing dependency for sending: {e}")
    except Exception as e:
        raise click.ClickException(f"Transaction failed: {e}")


@cli.command("balance")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.option("--node", "-n", default="http://localhost:3007", help="Node RPC URL")
def balance_cmd(wallet_file: str, node: str):
    """Check wallet balance.
    
    Examples:
    
        qrdx-wallet balance wallet.json
        
        qrdx-wallet balance wallet.json --node http://node.qrdx.network:8000
    """
    wallet_path = Path(wallet_file)
    password = get_password(prompt="Enter wallet password: ")
    
    try:
        wallet = load_wallet(wallet_path, password)
    except WalletDecryptionError:
        raise click.ClickException("Invalid password")
    except Exception as e:
        raise click.ClickException(f"Failed to load wallet: {e}")
    
    # Get addresses to check
    addresses = []
    if isinstance(wallet, UnifiedWallet):
        if wallet.traditional:
            addresses.append(("Traditional", wallet.traditional.address))
        if wallet.pq:
            addresses.append(("PQ", wallet.pq.address))
    else:
        addresses.append(("", wallet.address))
    
    click.echo()
    click.echo(f"Checking balance from node: {node}")
    click.echo()
    
    # Try to fetch balance from node
    try:
        import httpx
        
        for label, address in addresses:
            response = httpx.post(
                f"{node}/rpc",
                json={
                    "jsonrpc": "2.0",
                    "method": "qrdx_getBalance",
                    "params": [address],
                    "id": 1
                },
                timeout=10.0
            )
            
            if response.status_code == 200:
                result = response.json()
                if "result" in result:
                    balance = result["result"]
                    prefix = f"{label}: " if label else ""
                    click.echo(f"{prefix}{address}")
                    click.echo(f"  Balance: {balance} QRDX")
                else:
                    click.echo(f"{address}: Error - {result.get('error', {}).get('message', 'Unknown error')}")
            else:
                click.echo(f"{address}: Failed to fetch (HTTP {response.status_code})")
        
    except ImportError:
        click.echo("Install httpx to check balance: pip install httpx")
        click.echo()
        for label, address in addresses:
            prefix = f"{label}: " if label else ""
            click.echo(f"{prefix}{address}")
    except Exception as e:
        click.echo(f"Failed to connect to node: {e}")
        click.echo()
        for label, address in addresses:
            prefix = f"{label}: " if label else ""
            click.echo(f"{prefix}{address}")


@cli.command("sign")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("message")
@click.option(
    "--type", "-t",
    "wallet_type",
    type=click.Choice(["traditional", "pq"]),
    default="traditional",
    help="Which wallet to use for signing (for unified wallets)"
)
@click.option("--hex", "as_hex", is_flag=True, help="Output signature as hex")
def sign_cmd(wallet_file: str, message: str, wallet_type: str, as_hex: bool):
    """Sign a message with wallet.
    
    Examples:
    
        qrdx-wallet sign wallet.json "Hello, QRDX!"
        
        qrdx-wallet sign wallet.json "data" --type pq --hex
    """
    wallet_path = Path(wallet_file)
    password = get_password(prompt="Enter wallet password: ")
    
    try:
        wallet = load_wallet(wallet_path, password)
    except WalletDecryptionError:
        raise click.ClickException("Invalid password")
    except Exception as e:
        raise click.ClickException(f"Failed to load wallet: {e}")
    
    # Get appropriate wallet for signing
    if isinstance(wallet, UnifiedWallet):
        wtype = WalletType.TRADITIONAL if wallet_type == "traditional" else WalletType.POST_QUANTUM
        try:
            signing_wallet = wallet.get_wallet(wtype)
        except WalletError:
            raise click.ClickException(f"This unified wallet doesn't have a {wallet_type} key")
    else:
        signing_wallet = wallet
    
    # Sign message
    message_bytes = message.encode('utf-8')
    signature = signing_wallet.sign(message_bytes)
    
    click.echo()
    click.echo(f"Message: {message}")
    click.echo(f"Signer: {signing_wallet.address}")
    
    if as_hex:
        click.echo(f"Signature: 0x{signature.hex()}")
    else:
        import base64
        click.echo(f"Signature (base64): {base64.b64encode(signature).decode()}")


@cli.command("export")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["hex", "keystore"]),
    default="keystore",
    help="Export format"
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def export_cmd(wallet_file: str, output_format: str, output: Optional[str]):
    """Export wallet to different formats.
    
    WARNING: Exported private keys are sensitive!
    
    Examples:
    
        qrdx-wallet export wallet.json --format keystore -o backup.json
        
        qrdx-wallet export wallet.json --format hex
    """
    wallet_path = Path(wallet_file)
    password = get_password(prompt="Enter wallet password: ")
    
    try:
        wallet = load_wallet(wallet_path, password)
    except WalletDecryptionError:
        raise click.ClickException("Invalid password")
    except Exception as e:
        raise click.ClickException(f"Failed to load wallet: {e}")
    
    if output_format == "hex":
        click.echo()
        click.echo(click.style("⚠️  WARNING: Private key will be displayed!", fg="red", bold=True))
        if not click.confirm("Continue?"):
            return
        
        click.echo()
        if isinstance(wallet, UnifiedWallet):
            if wallet.traditional:
                click.echo(f"Traditional: 0x{wallet.traditional.export_private_key().hex()}")
            if wallet.pq:
                pq_hex = wallet.pq.export_private_key().hex()
                click.echo(f"PQ: 0x{pq_hex[:64]}... (truncated, full key is {len(pq_hex)} chars)")
        else:
            click.echo(f"Private Key: 0x{wallet.export_private_key().hex()}")
    
    elif output_format == "keystore":
        new_password = get_password(confirm=True, prompt="New keystore password: ")
        
        if isinstance(wallet, UnifiedWallet):
            keystore = wallet.to_keystore(new_password)
        else:
            keystore = wallet.to_keystore(new_password)
        
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                json.dump(keystore, f, indent=2)
            click.echo(f"Exported to: {output_path}")
        else:
            click.echo(json.dumps(keystore, indent=2))


@cli.command("import")
@click.argument("private_key")
@click.option(
    "--type", "-t",
    "wallet_type",
    type=click.Choice(["traditional", "pq"]),
    default="traditional",
    help="Wallet type (traditional for secp256k1 keys, pq for Dilithium)"
)
@click.option("--name", "-n", default="Imported Wallet", help="Wallet name")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def import_cmd(private_key: str, wallet_type: str, name: str, output: Optional[str]):
    """Import wallet from private key.
    
    Examples:
    
        qrdx-wallet import 0x1234...abcd --type traditional
        
        qrdx-wallet import "mnemonic words here" --type traditional
    """
    # Detect if mnemonic
    words = private_key.split()
    if len(words) in (12, 24):
        # Mnemonic phrase
        if wallet_type != "traditional":
            raise click.ClickException("Mnemonic import only supported for traditional wallets")
        
        try:
            wallet = TraditionalWallet.from_mnemonic(" ".join(words))
        except WalletError as e:
            raise click.ClickException(str(e))
    else:
        # Hex private key
        key = private_key
        if key.startswith("0x"):
            key = key[2:]
        
        try:
            key_bytes = bytes.fromhex(key)
        except ValueError:
            raise click.ClickException("Invalid private key format")
        
        if wallet_type == "traditional":
            wallet = TraditionalWallet.from_private_key(key_bytes)
        else:
            wallet = PQWallet.from_private_key(key_bytes)
    
    password = get_password(confirm=True, prompt="Set wallet password: ")
    
    if output:
        wallet_path = Path(output)
    else:
        DEFAULT_WALLET_DIR.mkdir(parents=True, exist_ok=True)
        wallet_path = DEFAULT_WALLET_DIR / f"{wallet.address[:10]}.json"
    
    wallet.save(wallet_path, password)
    
    click.echo(click.style("✓ Wallet imported successfully!", fg="green"))
    click.echo(f"Address: {wallet.address}")
    click.echo(f"Saved to: {wallet_path}")


@cli.command("system-wallets")
@click.option("--node", "-n", default="http://localhost:3007", help="Node RPC URL")
def system_wallets_cmd(node: str):
    """List all system wallets and their balances.
    
    Examples:
    
        qrdx-wallet system-wallets
        
        qrdx-wallet system-wallets --node http://node.qrdx.network:3007
    """
    try:
        import httpx
        
        click.echo()
        click.echo(click.style("QRDX System Wallets", fg="cyan", bold=True))
        click.echo("=" * 80)
        
        # Get system wallet info from node
        response = httpx.post(
            f"{node}/rpc",
            json={
                "jsonrpc": "2.0",
                "method": "qrdx_getSystemWallets",
                "params": [],
                "id": 1
            },
            timeout=10.0
        )
        
        if response.status_code != 200:
            raise click.ClickException(f"Failed to fetch system wallets (HTTP {response.status_code})")
        
        result = response.json()
        if "error" in result:
            # Fallback to known addresses
            click.echo(click.style("⚠ Node doesn't support system wallet query, showing known addresses", fg="yellow"))
            click.echo()
            
            system_wallet_addresses = [
                ("0x0000000000000000000000000000000000000001", "Garbage Collector (Burner)"),
                ("0x0000000000000000000000000000000000000002", "Community Grants"),
                ("0x0000000000000000000000000000000000000003", "Developer Fund"),
                ("0x0000000000000000000000000000000000000004", "Ecosystem Fund"),
                ("0x0000000000000000000000000000000000000005", "Staking Rewards"),
                ("0x0000000000000000000000000000000000000006", "Marketing & Partnerships"),
                ("0x0000000000000000000000000000000000000007", "Liquidity Pool Reserve"),
                ("0x0000000000000000000000000000000000000008", "Treasury Multisig"),
                ("0x0000000000000000000000000000000000000009", "Bug Bounty Program"),
                ("0x000000000000000000000000000000000000000a", "Airdrop Distribution"),
            ]
            
            total_balance = 0
            for address, name in system_wallet_addresses:
                # Try to get balance
                try:
                    bal_response = httpx.post(
                        f"{node}/rpc",
                        json={
                            "jsonrpc": "2.0",
                            "method": "qrdx_getBalance",
                            "params": [address],
                            "id": 1
                        },
                        timeout=5.0
                    )
                    
                    if bal_response.status_code == 200:
                        bal_result = bal_response.json()
                        balance = bal_result.get("result", "unknown")
                        if balance != "unknown":
                            try:
                                total_balance += float(balance)
                            except (ValueError, TypeError):
                                pass
                    else:
                        balance = "unknown"
                except Exception:
                    balance = "unknown"
                
                click.echo(f"{name:30} {address:50} {balance:>15}")
            
            if total_balance > 0:
                click.echo("=" * 80)
                click.echo(f"{'Total':30} {' ':50} {total_balance:>15.2f}")
        else:
            wallets = result.get("result", [])
            controller = None
            
            click.echo()
            for wallet in wallets:
                address = wallet.get("address")
                name = wallet.get("name", "Unknown")
                balance = wallet.get("balance", "0")
                is_burner = wallet.get("is_burner", False)
                
                if controller is None:
                    controller = wallet.get("controller_address")
                
                burner_mark = " 🔥" if is_burner else ""
                click.echo(f"{name:30} {address:50} {balance:>15}{burner_mark}")
            
            click.echo()
            click.echo("=" * 80)
            if controller:
                click.echo(f"Controller: {controller}")
        
    except ImportError:
        click.echo("Install httpx to query system wallets: pip install httpx")
    except Exception as e:
        raise click.ClickException(f"Failed to fetch system wallets: {e}")


@cli.command("list")
@click.option("--dir", "-d", type=click.Path(), help="Wallet directory")
def list_cmd(dir: Optional[str]):
    """List all wallets in directory.
    
    Examples:
    
        qrdx-wallet list
        
        qrdx-wallet list --dir /path/to/wallets
    """
    wallet_dir = Path(dir) if dir else DEFAULT_WALLET_DIR
    
    if not wallet_dir.exists():
        click.echo(f"Wallet directory not found: {wallet_dir}")
        return
    
    wallets = list(wallet_dir.glob("*.json"))
    
    if not wallets:
        click.echo("No wallets found.")
        return
    
    click.echo()
    click.echo(f"Wallets in {wallet_dir}:")
    click.echo()
    
    for wallet_file in sorted(wallets):
        try:
            with open(wallet_file, 'r') as f:
                data = json.load(f)
            
            wallet_type = data.get('wallet_type', 'traditional')
            
            if wallet_type == 'unified':
                addresses = []
                if 'wallets' in data:
                    if 'traditional' in data['wallets']:
                        addr = data['wallets']['traditional'].get('address', '?')
                        addresses.append(f"0x{addr}" if not addr.startswith('0x') else addr)
                    if 'pq' in data['wallets']:
                        addr = data['wallets']['pq'].get('address', '?')
                        addresses.append(addr)
                click.echo(f"  {wallet_file.name}")
                click.echo(f"    Type: unified")
                for a in addresses:
                    click.echo(f"    Address: {format_address(a, short=True)}")
            else:
                addr = data.get('address', '?')
                if not addr.startswith('0x'):
                    addr = f"0x{addr}"
                click.echo(f"  {wallet_file.name}")
                click.echo(f"    Type: {wallet_type}")
                click.echo(f"    Address: {format_address(addr, short=True)}")
            
            click.echo()
            
        except Exception as e:
            click.echo(f"  {wallet_file.name} - Error: {e}")


# Perpetuals: qrdx-wallet perp … (qrdx/cli/perp.py)
from qrdx.cli.perp import perp as _perp_commands  # noqa: E402

cli.add_command(_perp_commands)

# Native tokens: qrdx-wallet token … (qrdx/cli/token.py)
from qrdx.cli.token import token as _token_commands  # noqa: E402

cli.add_command(_token_commands)

# Native NFTs: qrdx-wallet nft … (qrdx/cli/nft.py)
from qrdx.cli.nft import nft as _nft_commands  # noqa: E402

cli.add_command(_nft_commands)

# Spot: qrdx-wallet spot … (qrdx/cli/spot.py)
from qrdx.cli.spot import spot as _spot_commands  # noqa: E402

cli.add_command(_spot_commands)

# Governance: qrdx-wallet gov … (qrdx/cli/gov.py)
from qrdx.cli.gov import gov as _gov_commands  # noqa: E402

cli.add_command(_gov_commands)


@cli.command("generate-mnemonic")
@click.option("--words", "-w", type=click.Choice(["12", "24"]), default="12", help="Number of words")
def generate_mnemonic_cmd(words: str):
    """Generate a new BIP-39 mnemonic phrase.
    
    Examples:
    
        qrdx-wallet generate-mnemonic
        
        qrdx-wallet generate-mnemonic --words 24
    """
    from qrdx.wallet_v2.traditional import generate_mnemonic
    
    strength = 128 if words == "12" else 256
    
    try:
        mnemonic = generate_mnemonic(strength)
    except WalletError as e:
        raise click.ClickException(str(e))
    
    click.echo()
    click.echo(click.style("Generated Mnemonic Phrase:", fg="green", bold=True))
    click.echo()
    
    word_list = mnemonic.split()
    for i, word in enumerate(word_list, 1):
        click.echo(f"  {i:2}. {word}")
    
    click.echo()
    click.echo(click.style("⚠️  IMPORTANT: Write down these words and store them safely!", fg="yellow"))
    click.echo(click.style("   Anyone with this phrase can access your wallet.", fg="yellow"))


if __name__ == "__main__":
    cli()
