import csv
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.aes_service import decrypt_aes_256_gcm, encrypt_aes_256_gcm, generate_aes_key
from app.services.rsa_service import generate_rsa_keypair
from app.services.signature_service import sign, verify

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "reports" / "metrics"
OUTPUT.mkdir(parents=True, exist_ok=True)

data = b"SecureSign experimental payload. " * 32_768  # approximately 1 MiB
key = generate_aes_key(256)
private_key, public_key = generate_rsa_keypair(2048)
rows = []

for iteration in range(30):
    start = time.perf_counter()
    encrypted = encrypt_aes_256_gcm(data, key)
    encrypt_ms = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    recovered = decrypt_aes_256_gcm(encrypted, key)
    decrypt_ms = (time.perf_counter() - start) * 1000

    signature = sign(data, private_key)
    start = time.perf_counter()
    valid = verify(data, signature, public_key)
    verify_ms = (time.perf_counter() - start) * 1000
    tamper_detected = not verify(data + b"x", signature, public_key)
    assert recovered == data and valid
    rows.append(
        {
            "iteration": iteration + 1,
            "encrypt_ms": round(encrypt_ms, 4),
            "decrypt_ms": round(decrypt_ms, 4),
            "signature_verify_ms": round(verify_ms, 4),
            "tamper_detected": int(tamper_detected),
        }
    )

with (OUTPUT / "benchmark.csv").open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

summary = {
    "payload_bytes": len(data),
    "iterations": len(rows),
    "mean_encrypt_ms": statistics.mean(row["encrypt_ms"] for row in rows),
    "stdev_encrypt_ms": statistics.stdev(row["encrypt_ms"] for row in rows),
    "mean_decrypt_ms": statistics.mean(row["decrypt_ms"] for row in rows),
    "mean_verify_ms": statistics.mean(row["signature_verify_ms"] for row in rows),
    "tamper_detection_percent": statistics.mean(row["tamper_detected"] for row in rows) * 100,
}
with (OUTPUT / "summary.txt").open("w", encoding="utf-8") as handle:
    for key_name, value in summary.items():
        handle.write(f"{key_name}={value:.4f}\n" if isinstance(value, float) else f"{key_name}={value}\n")
print(summary)
