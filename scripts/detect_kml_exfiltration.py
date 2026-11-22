"""
Automated KML Exfiltration Anomaly Detector.

Membaca dataset log simulasi Google Earth dan menandai akun/IP yang melakukan
aktivitas EXPORT_KML melebihi ambang batas (threshold).
"""

import argparse
import csv
from collections import defaultdict
from pathlib import Path


def detect_kml_exfiltration(log_file: Path, threshold: int = 5) -> list[dict]:
    """Memfilter log aktivitas dan mengembalikan daftar aktor di atas ambang batas."""
    export_counts: dict[tuple[str, str], int] = defaultdict(int)
    suspicious_actors: list[dict] = []

    with log_file.open(mode="r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row.get("action") == "EXPORT_KML":
                key = (row["user_email"], row["source_ip"])
                export_counts[key] += 1

    for (user, ip), count in export_counts.items():
        if count >= threshold:
            suspicious_actors.append(
                {"user": user, "ip": ip, "exports": count}
            )

    return suspicious_actors


def main() -> None:
    default_log_path = (
        Path(__file__).resolve().parent.parent / "data" / "simulated_earth_logs.csv"
    )

    parser = argparse.ArgumentParser(
        description="Deteksi anomali ekspor KML massal pada log simulasi."
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=default_log_path,
        help="Path ke file CSV log simulasi.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Ambang batas minimum jumlah EXPORT_KML untuk memicu alert (default: 5).",
    )
    args = parser.parse_args()

    if not args.log_file.exists():
        raise FileNotFoundError(f"File log tidak ditemukan: {args.log_file}")

    alerts = detect_kml_exfiltration(args.log_file, threshold=args.threshold)

    if not alerts:
        print("[OK] Tidak ditemukan anomali ekspor KML melebihi ambang batas.")
        return

    for alert in alerts:
        print(
            f"[ALERT] Anomali Terdeteksi! "
            f"User: {alert['user']} | IP: {alert['ip']} | "
            f"Total KML Exports: {alert['exports']}"
        )


if __name__ == "__main__":
    main()