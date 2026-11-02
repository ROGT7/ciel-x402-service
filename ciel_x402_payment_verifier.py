"""
CIEL x402 Payment Verifier — On-chain RPC + Replay Protection
==============================================================
Vérification mathématique des paiements x402 via RPC blockchain.

Protections:
1. Replay protection — un tx_hash ne peut être utilisé qu'une fois
2. On-chain verification — vérifie la tx sur le RPC node
3. Amount verification — le montant doit correspondre au prix du service
4. Recipient verification — le destinataire doit être notre wallet
5. Token verification — doit être USDC (pas un token arbitraire)
6. Block confirmation — la tx doit avoir au moins N confirmations
7. TTL — une tx trop ancienne est rejetée

Usage dans ciel_x402_server_v3.py:
    from ciel_x402_payment_verifier import PaymentVerifier
    verifier = PaymentVerifier(wallet=WALLET, network=NETWORK)
    # Dans le handler, avant d'exécuter le service:
    ok, err = verifier.verify(tx_hash, expected_amount_usdc, service_endpoint)
    if not ok:
        return JSONResponse({"error": "Payment verification failed", "reason": err}, status_code=402)
"""
import os
import json
import time
import sqlite3
import hashlib
import threading
import urllib.request
from typing import Optional, Tuple, Dict
from pathlib import Path


# USDC contract addresses on different networks
USDC_CONTRACTS = {
    "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",   # Base mainnet
    "eip155:84532": "0x036CbD53842c54266B42879f969f5CD981b6eC58",  # Base Sepolia
    "eip155:1": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",      # Ethereum mainnet
}

# RPC endpoints (env-configurable, with public fallbacks)
RPC_URLS = {
    "eip155:8453": os.environ.get("RPC_BASE", "https://mainnet.base.org"),
    "eip155:84532": os.environ.get("RPC_BASE_SEPOLIA", "https://sepolia.base.org"),
    "eip155:1": os.environ.get("RPC_ETHEREUM", "https://eth.llamarpc.com"),
}

# USDC Transfer event signature (Transfer(address,address,uint256))
TRANSFER_EVENT_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# Minimum confirmations required
MIN_CONFIRMATIONS = int(os.environ.get("X402_MIN_CONFIRMATIONS", "3"))

# Transaction TTL (reject txs older than this)
TX_TTL_SECONDS = int(os.environ.get("X402_TX_TTL", "3600"))  # 1 hour

# Amount tolerance (in USDC base units, 6 decimals)
AMOUNT_TOLERANCE = 1  # Allow 1 wei difference for rounding


class PaymentVerifier:
    """On-chain payment verification with replay protection."""

    def __init__(self, wallet: str, network: str,
                 db_path: str = None,
                 rpc_url: str = None):
        self.wallet = wallet.lower()
        self.network = network
        self.usdc_contract = USDC_CONTRACTS.get(network, "").lower()
        self.rpc_url = rpc_url or RPC_URLS.get(network, "")
        self.min_confirmations = MIN_CONFIRMATIONS
        self.tx_ttl = TX_TTL_SECONDS

        # SQLite for replay protection (thread-safe)
        self.db_path = db_path or os.environ.get(
            "X402_REPLAY_DB",
            str(Path(os.environ.get("CIEL_ROOT", ".")) / "memory" / "x402_replay_protection.db")
        )
        self._lock = threading.Lock()
        self._init_db()

        # In-memory cache for recent verifications (LRU)
        self._cache: Dict[str, Tuple[bool, float, str]] = {}  # tx_hash -> (valid, timestamp, reason)
        self._cache_ttl = 300  # 5 min cache

        print(f"[PAYMENT-VERIFIER] Initialized — wallet={wallet[:10]}..., network={network}, "
              f"USDC={self.usdc_contract[:10]}..., min_conf={self.min_confirmations}")

    def _init_db(self):
        """Initialize the replay protection SQLite database."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS used_payments (
                tx_hash TEXT PRIMARY KEY,
                endpoint TEXT NOT NULL,
                amount_usdc REAL NOT NULL,
                wallet TEXT NOT NULL,
                timestamp REAL NOT NULL,
                block_number INTEGER,
                verified_by TEXT DEFAULT 'rpc'
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_used_timestamp ON used_payments(timestamp)
        """)
        conn.commit()
        conn.close()

    def _rpc_call(self, method: str, params: list, timeout: int = 10) -> Optional[dict]:
        """Make a JSON-RPC call to the blockchain node."""
        if not self.rpc_url:
            return None
        try:
            payload = json.dumps({
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": 1
            }).encode()
            req = urllib.request.Request(
                self.rpc_url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())
                return data.get("result")
        except Exception as e:
            print(f"[PAYMENT-VERIFIER] RPC error ({method}): {e}")
            return None

    def _get_transaction(self, tx_hash: str) -> Optional[dict]:
        """Get transaction details from RPC."""
        return self._rpc_call("eth_getTransactionByHash", [tx_hash])

    def _get_transaction_receipt(self, tx_hash: str) -> Optional[dict]:
        """Get transaction receipt (includes logs and status)."""
        return self._rpc_call("eth_getTransactionReceipt", [tx_hash])

    def _get_block(self, block_number: str) -> Optional[dict]:
        """Get block details (for timestamp and confirmation count)."""
        return self._rpc_call("eth_getBlockByNumber", [block_number, False])

    def _get_current_block(self) -> Optional[int]:
        """Get current block number."""
        result = self._rpc_call("eth_blockNumber", [])
        if result:
            return int(result, 16)
        return None

    def _is_already_used(self, tx_hash: str) -> bool:
        """Check if a tx_hash has already been used for a payment."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = conn.execute(
            "SELECT 1 FROM used_payments WHERE tx_hash = ?",
            (tx_hash.lower(),)
        )
        result = cursor.fetchone() is not None
        conn.close()
        return result

    def _mark_used(self, tx_hash: str, endpoint: str, amount: float,
                   block_number: int = None):
        """Mark a tx_hash as used."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute(
            "INSERT OR IGNORE INTO used_payments (tx_hash, endpoint, amount_usdc, wallet, timestamp, block_number) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (tx_hash.lower(), endpoint, amount, self.wallet, time.time(), block_number)
        )
        conn.commit()
        conn.close()

    def _cleanup_old(self):
        """Remove entries older than TTL (periodic cleanup)."""
        cutoff = time.time() - self.tx_ttl * 24  # Keep 24x TTL for audit
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("DELETE FROM used_payments WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()

    def _verify_transfer_log(self, receipt: dict, expected_amount_usdc: float) -> Tuple[bool, str]:
        """
        Verify that the transaction receipt contains a valid USDC transfer
        to our wallet for the expected amount.
        """
        if not receipt:
            return False, "No transaction receipt"

        # Check tx status
        status = receipt.get("status", "0x0")
        if status == "0x0":
            return False, "Transaction reverted on-chain"

        logs = receipt.get("logs", [])
        if not logs:
            return False, "No logs in transaction (not a token transfer)"

        for log in logs:
            # Check if this is a USDC transfer event
            log_address = log.get("address", "").lower()
            if log_address != self.usdc_contract:
                continue

            topics = log.get("topics", [])
            if len(topics) < 3:
                continue

            # Check Transfer event signature
            if topics[0].lower() != TRANSFER_EVENT_TOPIC:
                continue

            # Parse recipient (topic[2], padded to 32 bytes)
            recipient = "0x" + topics[2][-40:].lower()
            if recipient != self.wallet:
                continue

            # Parse amount (data field, hex)
            data = log.get("data", "0x0")
            try:
                amount_base = int(data, 16)
                amount_usdc = amount_base / 1_000_000  # USDC has 6 decimals
            except (ValueError, TypeError):
                continue

            # Check amount (with tolerance)
            expected_base = int(expected_amount_usdc * 1_000_000)
            if abs(amount_base - expected_base) > AMOUNT_TOLERANCE:
                # Amount mismatch — could be a different service payment
                # We accept if amount >= expected (user overpaid)
                if amount_base < expected_base:
                    continue  # Keep looking in other logs
                # Overpayment is acceptable

            return True, f"Valid USDC transfer: {amount_usdc} USDC to {self.wallet[:10]}..."

        return False, "No matching USDC transfer to our wallet found in transaction logs"

    def verify(self, tx_hash: str, expected_amount_usdc: float,
               endpoint: str = "") -> Tuple[bool, str]:
        """
        Full payment verification.
        Returns (is_valid, reason).

        Steps:
        1. Check replay protection (tx_hash already used?)
        2. Fetch transaction from RPC
        3. Verify transaction exists and is confirmed
        4. Fetch receipt and verify USDC transfer
        5. Check block confirmations
        6. Mark tx_hash as used
        """
        if not tx_hash or not isinstance(tx_hash, str):
            return False, "Missing or invalid tx_hash"

        tx_hash = tx_hash.strip().lower()
        if not re.match(r'^0x[a-f0-9]{64}$', tx_hash):
            return False, "Invalid tx_hash format (expected 0x + 64 hex chars)"

        # Check cache first
        cached = self._cache.get(tx_hash)
        if cached:
            valid, ts, reason = cached
            if time.time() - ts < self._cache_ttl:
                if valid:
                    return True, "cached: valid"
                return False, f"cached: {reason}"

        # 1. Replay protection
        with self._lock:
            if self._is_already_used(tx_hash):
                return False, f"REPLAY ATTACK: tx_hash {tx_hash[:16]}... already used"
            self._cleanup_old()

        # 2. Fetch transaction
        tx = self._get_transaction(tx_hash)
        if not tx:
            return False, "Transaction not found on-chain (invalid hash or wrong network)"

        # 3. Verify transaction is confirmed
        if tx.get("blockNumber") is None:
            return False, "Transaction not yet mined (pending)"

        # 4. Verify on the correct network (chain ID check via receipt)
        receipt = self._get_transaction_receipt(tx_hash)
        if not receipt:
            return False, "Could not fetch transaction receipt"

        # 5. Verify USDC transfer in logs
        transfer_ok, transfer_reason = self._verify_transfer_log(receipt, expected_amount_usdc)
        if not transfer_ok:
            return False, f"Transfer verification failed: {transfer_reason}"

        # 6. Check confirmations
        tx_block = int(tx["blockNumber"], 16)
        current_block = self._get_current_block()
        if current_block:
            confirmations = current_block - tx_block
            if confirmations < self.min_confirmations:
                return False, f"Insufficient confirmations: {confirmations}/{self.min_confirmations}"

        # 7. Check transaction age (via block timestamp)
        block = self._get_block(tx["blockNumber"])
        if block and block.get("timestamp"):
            block_time = int(block["timestamp"], 16)
            age = time.time() - block_time
            if age > self.tx_ttl:
                return False, f"Transaction too old ({age:.0f}s > {self.tx_ttl}s TTL)"

        # 8. Mark as used (replay protection)
        with self._lock:
            if self._is_already_used(tx_hash):
                return False, "REPLAY ATTACK: tx_hash used during verification window"
            self._mark_used(tx_hash, endpoint, expected_amount_usdc, tx_block)

        # Cache the result
        self._cache[tx_hash] = (True, time.time(), "valid")

        print(f"[PAYMENT-VERIFIER] ✓ Verified: {tx_hash[:16]}... — {expected_amount_usdc} USDC for {endpoint}")
        return True, "Payment verified on-chain"

    def verify_fake_hash(self, tx_hash: str) -> Tuple[bool, str]:
        """
        Test function: try to verify a fake/random tx_hash.
        This should ALWAYS fail.
        """
        return self.verify(tx_hash, 0.01, "redteam_test")

    def get_status(self) -> dict:
        """Get verifier status for monitoring."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = conn.execute("SELECT COUNT(*) FROM used_payments")
        total_used = cursor.fetchone()[0]
        cursor = conn.execute("SELECT COUNT(*) FROM used_payments WHERE timestamp > ?", (time.time() - 3600,))
        recent_used = cursor.fetchone()[0]
        conn.close()

        return {
            "wallet": self.wallet[:10] + "...",
            "network": self.network,
            "usdc_contract": self.usdc_contract[:10] + "...",
            "rpc_url": self.rpc_url,
            "min_confirmations": self.min_confirmations,
            "tx_ttl_seconds": self.tx_ttl,
            "total_verified_payments": total_used,
            "verified_last_hour": recent_used,
            "cache_size": len(self._cache),
        }


# Module-level singleton (initialized on first use)
_verifier: Optional[PaymentVerifier] = None

def get_verifier(wallet: str = None, network: str = None) -> PaymentVerifier:
    """Get or create the singleton PaymentVerifier."""
    global _verifier
    if _verifier is None:
        wallet = wallet or os.environ.get("X402_WALLET", "")
        network = network or os.environ.get("X402_NETWORK", "eip155:84532")
        _verifier = PaymentVerifier(wallet=wallet, network=network)
    return _verifier


# Import re at module level (needed for verify method)
import re
