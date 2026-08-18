#!/usr/bin/env python3
import os
import sys
import time
import subprocess

def find_executable(name):
    # Search common build paths for the executable
    paths = [
        os.path.join("build", name),
        os.path.join("build", "Release", name),
        os.path.join("build", "Debug", name),
        os.path.join("build", "tests", name),
        name
    ]
    for p in paths:
        if os.path.exists(p):
            return p
        if os.path.exists(p + ".exe"):
            return p + ".exe"
    return None

def main():
    print("=== DPI Engine Performance Benchmarker ===")
    
    # 1. Locate binaries
    simple_bin = find_executable("dpi_simple")
    modular_bin = find_executable("dpi_modular")
    
    if not simple_bin:
        print("Error: Could not locate 'dpi_simple' binary. Please build the project first.")
        sys.exit(1)
        
    print(f"Found 'dpi_simple' at: {simple_bin}")
    if modular_bin:
        print(f"Found 'dpi_modular' at: {modular_bin}")
    else:
        print("Note: 'dpi_modular' not found. Multi-threaded benchmarks will be skipped (possibly due to toolchain limitations).")
        
    # 2. Generate benchmark PCAP
    pcap_filename = "benchmark.pcap"
    scale = 500  # multiplier to generate 38,500 packets
    total_packets = 77 * scale
    
    print(f"Generating deterministic benchmark dataset ({total_packets} packets)...")
    try:
        subprocess.run([sys.executable, "generate_test_pcap.py", pcap_filename, str(scale)], check=True)
    except Exception as e:
        print(f"Error generating benchmark PCAP: {e}")
        sys.exit(1)
        
    if not os.path.exists(pcap_filename):
        print(f"Error: {pcap_filename} was not generated.")
        sys.exit(1)
        
    pcap_size_bytes = os.path.getsize(pcap_filename)
    pcap_size_mb = pcap_size_bytes / (1024 * 1024)
    print(f"Dataset generated successfully. Size: {pcap_size_mb:.2f} MB")
    
    # 3. Benchmark runner
    results = []
    
    # Configurations to run: (Name, Bin, Args)
    configs = [
        ("Single-threaded", simple_bin, [])
    ]
    
    if modular_bin:
        configs.extend([
            ("Modular 2 LB / 2 FP", modular_bin, ["--lbs", "2", "--fps", "2"]),
            ("Modular 2 LB / 4 FP", modular_bin, ["--lbs", "2", "--fps", "4"]),
            ("Modular 2 LB / 8 FP", modular_bin, ["--lbs", "2", "--fps", "8"]),
        ])
        
    for name, bin_path, args in configs:
        out_pcap = f"out_{name.replace(' ', '_').lower()}.pcap"
        cmd = [bin_path, pcap_filename, out_pcap] + args
        
        print(f"Running benchmark: {name}...")
        start_time = time.perf_counter()
        try:
            # Redirect stdout/stderr to hide noisy prints during timing
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            elapsed = time.perf_counter() - start_time
            
            # Calculate stats
            pkts_per_sec = total_packets / elapsed
            mb_per_sec = pcap_size_mb / elapsed
            
            results.append({
                "config": name,
                "status": "Success",
                "time": f"{elapsed:.3f}s",
                "pkts_sec": f"{pkts_per_sec:,.1f}",
                "mb_sec": f"{mb_per_sec:.2f} MB/s",
                "notes": ""
            })
        except subprocess.CalledProcessError as e:
            results.append({
                "config": name,
                "status": "Failed",
                "time": "N/A",
                "pkts_sec": "N/A",
                "mb_sec": "N/A",
                "notes": f"Exit code {e.returncode}"
            })
        except Exception as e:
            results.append({
                "config": name,
                "status": "Error",
                "time": "N/A",
                "pkts_sec": "N/A",
                "mb_sec": "N/A",
                "notes": str(e)
            })
            
        # Cleanup output files
        if os.path.exists(out_pcap):
            try:
                os.remove(out_pcap)
            except:
                pass
                
    # Cleanup benchmark pcap
    if os.path.exists(pcap_filename):
        try:
            os.remove(pcap_filename)
        except:
            pass
            
    # 4. Report Results in Markdown
    print("\n=== BENCHMARK RESULTS ===")
    markdown_table = [
        "| Configuration | Status | Time (s) | Throughput (Packets/s) | Speed (MB/s) | Notes |",
        "| --- | --- | --- | --- | --- | --- |"
    ]
    for r in results:
        markdown_table.append(f"| {r['config']} | {r['status']} | {r['time']} | {r['pkts_sec']} | {r['mb_sec']} | {r['notes']} |")
        
    report = "\n".join(markdown_table)
    print(report)
    
    # Save report to artifacts directory if running under agent system
    with open("benchmark_results.md", "w") as f:
        f.write("# Performance Benchmark Results\n\n")
        f.write(f"Generated at: {time.asctime()}\n")
        f.write(f"Benchmark Dataset Size: {pcap_size_mb:.2f} MB ({total_packets:,} packets)\n\n")
        f.write(report)
        f.write("\n")
        
    print("\nResults saved to 'benchmark_results.md'.")

if __name__ == "__main__":
    main()
