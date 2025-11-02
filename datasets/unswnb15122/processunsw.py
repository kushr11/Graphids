import os
import csv
import argparse
import subprocess
from pathlib import Path

def check_tshark():
    from shutil import which
    if which("tshark") is None:
        raise RuntimeError("tshark not found. Install Wireshark/tshark and ensure it's in PATH.")

def make_filter(start, end, row, pad):
    s = f"(frame.time_epoch >= {start - pad} && frame.time_epoch <= {end + pad})"
    # add ip/port filters if provided
    parts = [s]
    proto = (row.get("Protocol") or row.get("protocol") or "").strip()
    src_ip = (row.get("Source IP") or row.get("src_ip") or "").strip()
    dst_ip = (row.get("Destination IP") or row.get("dst_ip") or "").strip()
    src_port = (row.get("Source Port") or row.get("src_port") or "").strip()
    dst_port = (row.get("Destination Port") or row.get("dst_port") or "").strip()

    if proto:
        proto = proto.lower()
        if proto in ("tcp","udp","icmp","http"):
            parts.append(proto)
    if src_ip:
        parts.append(f"ip.src == {src_ip}")
    if dst_ip:
        parts.append(f"ip.dst == {dst_ip}")
    # tshark uses tcp.srcport / udp.srcport etc
    if src_port:
        parts.append(f"(tcp.srcport == {src_port} or udp.srcport == {src_port})")
    if dst_port:
        parts.append(f"(tcp.dstport == {dst_port} or udp.dstport == {dst_port})")
    return " && ".join(parts)

def extract_segment(pcap_file, out_file, tshark_filter):
    cmd = ["tshark", "-r", str(pcap_file), "-Y", tshark_filter, "-w", str(out_file)]
    # run tshark and return True if produced file with size>0
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print("tshark failed:", e)
        return False
    return out_file.exists() and out_file.stat().st_size > 24  # small pcap header size

def main(args):
    check_tshark()
    csv_path = Path(args.csv)
    src_pcap = Path(args.pcap)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(csv_path, newline='', encoding=args.encoding) as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            # try to read Start/Last time columns (adjust names if different)
            try:
                start = float(row.get("Start time") or row.get("Start time".lower()) or row.get("Start time".upper()) or row.get("Start Time") or row.get("Start_time") or row.get("Start"))
                end = float(row.get("Last time") or row.get("Last time".lower()) or row.get("Last Time") or row.get("Last_time") or row.get("Last"))
            except Exception:
                print(f"Skipping row {i}: cannot parse start/end time.")
                continue

            label = row.get("Attack category") or row.get("Attack Category") or row.get("Attack category".lower()) or "unknown"
            label = label.strip() or "unknown"
            label_dir = out_dir / label
            label_dir.mkdir(parents=True, exist_ok=True)

            safe_name = f"{i:06d}_{row.get('Attack Name','').strip()[:80].replace('/', '_').replace(' ', '_')}"
            out_file = label_dir / (safe_name + ".pcap")

            filt = make_filter(start, end, row, args.pad)
            success = extract_segment(src_pcap, out_file, filt)
            if not success:
                # fallback: try only time-range without ip/port/proto constraints
                time_only = f"(frame.time_epoch >= {start - args.pad} && frame.time_epoch <= {end + args.pad})"
                success = extract_segment(src_pcap, out_file, time_only)
            if success:
                print("WROTE:", out_file, "label=", label)
            else:
                # keep note for manual inspection
                print("NO PACKETS for row", i, "label", label, "->", out_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", default="AI4security/Second_graph_based_nids/ET-BERT/datasets/unswnb15122/1.pcap", help="原始大 pcap 文件路径（或单个 pcap）")
    parser.add_argument("--csv", default="AI4security/Second_graph_based_nids/ET-BERT/datasets/unswnb15122/NUSW-NB15_GT.csv", help="CSV 文件路径（含 Start time / Last time 列）")
    parser.add_argument("--out", default="AI4security/Second_graph_based_nids/ET-BERT/datasets/unswnb15122/labelds", help="输出目录（将按 label 创建子目录）")
    parser.add_argument("--pad", type=float, default=0.5, help="每个事件前后扩展多少秒（默认0.5s）")
    parser.add_argument("--encoding", default="utf-8", help="CSV 编码")
    args = parser.parse_args()
    main(args)