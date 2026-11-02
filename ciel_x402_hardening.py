"""
CIEL x402 Hardening — Dynamic Pricing + Response Signing + Auto-Sweep + Swarm
==============================================================================
Module de blindage avancé pour le serveur x402:

1. DynamicPricingEngine — Prix calculé à la volée (CPU + gas + marge)
2. ResponseSigner — Signature HMAC des réponses pour SLA trust
3. AutoSweep — Transfert automatique des USDC excédentaires vers cold wallet
4. SwarmRouter — Chainage interne entre services (auto-guérison)

Usage dans ciel_x402_server_v3.py:
    from ciel_x402_hardening import DynamicPricingEngine, ResponseSigner, AutoSweep, SwarmRouter

    pricing = DynamicPricingEngine()
    signer = ResponseSigner(secret=os.environ["X402_SIGNING_KEY"])
    sweeper = AutoSweep(cold_wallet=os.environ["X402_COLD_WALLET"])
    swarm = SwarmRouter(service_registry=services)
"""
import os
import time
import json
import hmac
import hashlib
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field


# ============================================================
# 1. DYNAMIC PRICING ENGINE
# ============================================================

class DynamicPricingEngine:
    """Calcule le prix x402 à la volée: Prix = (CPU × coût) + Gas + Marge."""

    # Cost per ms of CPU time (in USDC cents)
    CPU_COST_PER_MS = 0.001  # 0.001 cent per ms = $0.01 per 10s of CPU

    # Gas cost estimates per network (in USDC cents)
    GAS_COSTS = {
        "base": 0.1,      # Base L2 ~$0.001 per tx
        "ethereum": 50.0,  # Mainnet ~$0.50 per tx
        "arbitrum": 0.2,
        "optimism": 0.15,
        "polygon": 0.05,
    }

    # Default margin percentage
    DEFAULT_MARGIN_PCT = 30

    # Category-based base prices (in USDC cents) — fallback
    CATEGORY_BASE = {
        "stealth": 5,      # $0.05
        "defi": 10,        # $0.10
        "cognitive": 8,    # $0.08
        "security": 7,     # $0.07
        "saas": 3,         # $0.03
        "data": 2,         # $0.02
        "trading": 15,     # $0.15
        "default": 5,      # $0.05
    }

    def __init__(self, network: str = "base", margin_pct: int = None):
        self.network = network
        self.margin_pct = margin_pct or int(os.environ.get("X402_MARGIN_PCT", self.DEFAULT_MARGIN_PCT))
        self._latency_history: Dict[str, List[float]] = {}  # service -> [latencies]
        self._lock = threading.Lock()

    def estimate_price(self, service_id: str, category: str = "default",
                       estimated_cpu_ms: int = None, static_price: int = None) -> int:
        """Returns price in USDC cents (6 decimals = 1 USDC = 100 cents)."""
        # If we have latency history, use it
        if estimated_cpu_ms is None:
            with self._lock:
                history = self._latency_history.get(service_id, [])
                if history:
                    estimated_cpu_ms = sum(history[-20:]) / len(history[-20:])
                else:
                    estimated_cpu_ms = 100  # default 100ms

        cpu_cost = estimated_cpu_ms * self.CPU_COST_PER_MS
        gas_cost = self.GAS_COSTS.get(self.network, 0.1)
        base = cpu_cost + gas_cost
        margin = base * (self.margin_pct / 100)
        total = base + margin

        # Floor: never below category base price
        category_floor = self.CATEGORY_BASE.get(category, self.CATEGORY_BASE["default"])
        final = max(total, category_floor)

        # If static price is set and higher, use it (respect existing config)
        if static_price and static_price > final:
            final = static_price

        return int(final)

    def record_latency(self, service_id: str, latency_ms: float):
        with self._lock:
            if service_id not in self._latency_history:
                self._latency_history[service_id] = []
            self._latency_history[service_id].append(latency_ms)
            # Keep last 100
            if len(self._latency_history[service_id]) > 100:
                self._latency_history[service_id] = self._latency_history[service_id][-100:]

    def get_pricing_report(self) -> Dict:
        with self._lock:
            return {
                "network": self.network,
                "margin_pct": self.margin_pct,
                "tracked_services": len(self._latency_history),
                "avg_latencies": {
                    sid: round(sum(h) / len(h), 2)
                    for sid, h in self._latency_history.items() if h
                },
                "gas_costs": self.GAS_COSTS,
            }


# ============================================================
# 2. RESPONSE SIGNER — SLA Trust
# ============================================================

class ResponseSigner:
    """Signe les réponses JSON avec HMAC-SHA256 pour garantir l'authenticité."""

    def __init__(self, secret: str = None):
        self.secret = secret or os.environ.get("X402_SIGNING_KEY", "ciel-default-signing-key-change-me")
        self._signature_count = 0
        self._lock = threading.Lock()

    def sign(self, payload: Dict) -> Dict:
        """Add signature to response payload."""
        payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        signature = hmac.new(
            self.secret.encode(),
            payload_str.encode(),
            hashlib.sha256
        ).hexdigest()

        with self._lock:
            self._signature_count += 1

        return {
            **payload,
            "_meta": {
                "signed": True,
                "signature": signature,
                "signer": "ciel-x402",
                "timestamp": time.time(),
                "sig_id": self._signature_count,
            }
        }

    def verify(self, payload: Dict) -> bool:
        """Verify a signed response."""
        meta = payload.get("_meta", {})
        if not meta.get("signed"):
            return False
        signature = meta.get("signature", "")
        clean = {k: v for k, v in payload.items() if k != "_meta"}
        payload_str = json.dumps(clean, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(
            self.secret.encode(),
            payload_str.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected)

    def get_stats(self) -> Dict:
        with self._lock:
            return {"total_signed": self._signature_count}


# ============================================================
# 3. AUTO-SWEEP — Excess USDC → Cold Wallet
# ============================================================

class AutoSweep:
    """Transfert automatique du surplus USDC vers un cold wallet sécurisé."""

    def __init__(self, cold_wallet: str = None, threshold_usdc: float = 100.0,
                 check_interval_s: int = 300, network: str = "base"):
        self.cold_wallet = cold_wallet or os.environ.get("X402_COLD_WALLET", "")
        self.threshold = threshold_usdc
        self.check_interval = check_interval_s
        self.network = network
        self._running = False
        self._stop_event = threading.Event()
        self._sweep_history: List[Dict] = []

        if not self.cold_wallet:
            print("[AUTO-SWEEP] WARNING: No cold wallet configured — sweeps disabled")

    def get_balance(self) -> float:
        """Get USDC balance of the execution wallet."""
        try:
            from web3 import Web3
            rpc = os.environ.get(f"RPC_{self.network.upper()}", "https://mainnet.base.org")
            w3 = Web3(Web3.HTTPProvider(rpc))
            usdc_addr = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"  # Base USDC
            private_key = os.environ.get("X402_PRIVATE_KEY", "")
            if not private_key:
                return 0.0
            account = w3.eth.account.from_key(private_key)
            usdc_abi = [{"inputs": [{"name": "owner", "type": "address"}],
                         "name": "balanceOf", "outputs": [{"type": "uint256"}],
                         "type": "function", "stateMutability": "view"}]
            usdc = w3.eth.contract(
                address=Web3.to_checksum_address(usdc_addr), abi=usdc_abi
            )
            balance = usdc.functions.balanceOf(account.address).call()
            return balance / 1e6  # USDC has 6 decimals
        except Exception as e:
            print(f"[AUTO-SWEEP] Balance check error: {e}")
            return 0.0

    def sweep(self) -> Optional[Dict]:
        """Execute sweep if balance exceeds threshold."""
        if not self.cold_wallet:
            return None

        balance = self.get_balance()
        if balance <= self.threshold:
            return None

        surplus = balance - self.threshold
        print(f"[AUTO-SWEEP] Balance: ${balance:.2f} — Sweeping ${surplus:.2f} to cold wallet")

        try:
            from web3 import Web3
            rpc = os.environ.get(f"RPC_{self.network.upper()}", "https://mainnet.base.org")
            w3 = Web3(Web3.HTTPProvider(rpc))
            private_key = os.environ.get("X402_PRIVATE_KEY", "")
            account = w3.eth.account.from_key(private_key)

            usdc_addr = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
            usdc_abi = [{"inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}],
                         "name": "transfer", "outputs": [{"type": "bool"}], "type": "function"}]
            usdc = w3.eth.contract(
                address=Web3.to_checksum_address(usdc_addr), abi=usdc_abi
            )

            amount_wei = int(surplus * 1e6)
            nonce = w3.eth.get_transaction_count(account.address)
            tx = usdc.functions.transfer(
                Web3.to_checksum_address(self.cold_wallet), amount_wei
            ).build_transaction({
                "from": account.address,
                "nonce": nonce,
                "gas": 100000,
                "gasPrice": w3.eth.gas_price,
            })
            signed = account.sign_transaction(tx)
            tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

            sweep_record = {
                "timestamp": time.time(),
                "amount_usdc": surplus,
                "tx_hash": tx_hash.hex(),
                "to": self.cold_wallet,
                "block": receipt.blockNumber,
            }
            self._sweep_history.append(sweep_record)
            print(f"[AUTO-SWEEP] ✅ Swept ${surplus:.2f} — TX: {tx_hash.hex()}")
            return sweep_record
        except Exception as e:
            print(f"[AUTO-SWEEP] ❌ Sweep failed: {e}")
            return None

    def start_daemon(self):
        """Start background sweep checker."""
        self._running = True
        t = threading.Thread(target=self._sweep_loop, name="auto-sweep", daemon=True)
        t.start()
        print(f"[AUTO-SWEEP] Daemon started — threshold=${self.threshold}, interval={self.check_interval}s")

    def _sweep_loop(self):
        while not self._stop_event.is_set():
            try:
                self.sweep()
            except Exception as e:
                print(f"[AUTO-SWEEP] Loop error: {e}")
            self._stop_event.wait(timeout=self.check_interval)

    def stop(self):
        self._stop_event.set()

    def get_history(self) -> List[Dict]:
        return self._sweep_history


# ============================================================
# 4. SWARM ROUTER — Services calling services internally
# ============================================================

class SwarmRouter:
    """Permet aux services de s'appeler mutuellement pour auto-guérison.

    Exemple: Service 54 (CF Bypass) échoue → appelle Service 3 (Proxy) + Service 4 (Captcha)
    """

    # Chainage défini par catégorie — si un service échoue, essayer ces alternatives
    FALLBACK_CHAINS = {
        "stealth": ["stealth", "data", "security"],  # CF bypass → proxy → captcha
        "defi": ["defi", "data"],
        "cognitive": ["cognitive", "data"],
        "security": ["security", "data"],
        "saas": ["saas", "data"],
        "data": ["data"],
        "trading": ["trading", "defi", "data"],
    }

    def __init__(self, service_registry: List[Dict] = None,
                 service_handlers: Dict[str, Callable] = None):
        self.registry = service_registry or []
        self.handlers = service_handlers or {}
        self._chain_count = 0
        self._success_count = 0
        self._lock = threading.Lock()

    def register_handler(self, service_id: str, handler: Callable):
        self.handlers[service_id] = handler

    def execute_with_fallback(self, service_id: str, params: Dict,
                              max_attempts: int = 3) -> Dict:
        """Execute a service, and if it fails, try fallback services in the same category."""
        # Find the service info
        svc_info = None
        for s in self.registry:
            if str(s.get("id", "")) == str(service_id):
                svc_info = s
                break

        category = svc_info.get("category", "default") if svc_info else "default"
        fallback_categories = self.FALLBACK_CHAINS.get(category, [category])

        # Try primary service first
        handler = self.handlers.get(str(service_id))
        if handler:
            try:
                result = handler(params)
                with self._lock:
                    self._success_count += 1
                return result
            except Exception as e:
                print(f"[SWARM] Service {service_id} failed: {e} — trying fallbacks")

        # Try fallback services in same/related categories
        with self._lock:
            self._chain_count += 1

        for fb_cat in fallback_categories:
            if fb_cat == category:
                continue
            fallback_services = [
                s for s in self.registry
                if s.get("category") == fb_cat and str(s.get("id", "")) != str(service_id)
            ]
            for fb_svc in fallback_services[:2]:  # Try max 2 per fallback category
                fb_id = str(fb_svc.get("id", ""))
                fb_handler = self.handlers.get(fb_id)
                if fb_handler:
                    try:
                        print(f"[SWARM] Trying fallback: {fb_svc.get('name')} ({fb_id})")
                        result = fb_handler(params)
                        with self._lock:
                            self._success_count += 1
                        return result
                    except Exception as e:
                        print(f"[SWARM] Fallback {fb_id} also failed: {e}")
                        continue

        raise Exception(f"All swarm attempts failed for service {service_id}")

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                "total_chains": self._chain_count,
                "total_successes": self._success_count,
                "fallback_categories": self.FALLBACK_CHAINS,
            }
