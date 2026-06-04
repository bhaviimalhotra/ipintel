import csv
import os


def export_csv(rows, output_path):
    if not rows:
        print("[!] No data to export.")
        return

    # Create output directory if it doesn't exist
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n[✓] Exported {len(rows)} rows → {os.path.abspath(output_path)}")
