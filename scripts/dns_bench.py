import socket
import time
import threading
import sys
import argparse

def build_dns_query(domain):
    # Transaction ID: 0x1234
    # Flags: 0x0100 (Standard query, RD=1)
    # Questions: 1, Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"

    # Domain: example.com -> \x07example\x03com\x00
    qname = b""
    for part in domain.split("."):
        if part:
            qname += bytes([len(part)]) + part.encode()
    qname += b"\x00"

    # Type: A (1), Class: IN (1)
    question = qname + b"\x00\x01\x00\x01"
    return header + question

def worker(server_ip, server_port, qps, duration, results):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)

    query = build_dns_query("google.com")

    start_time = time.time()
    end_time = start_time + duration

    queries_sent = 0
    successes = 0
    latencies = []

    while time.time() < end_time:
        loop_start = time.time()

        try:
            sock.sendto(query, (server_ip, server_port))
            queries_sent += 1

            send_time = time.time()
            data, _ = sock.recvfrom(4096)
            latencies.append(time.time() - send_time)
            successes += 1
        except socket.timeout:
            pass
        except Exception as e:
            # print(f"Error: {e}")
            pass

        # Sleep to maintain QPS
        elapsed = time.time() - loop_start
        sleep_time = (1.0 / qps) - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)

    results["sent"] += queries_sent
    results["success"] += successes
    results["latencies"].extend(latencies)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5353)
    parser.add_argument("--qps", type=int, default=300)
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--threads", type=int, default=10)
    args = parser.parse_args()

    qps_per_thread = args.qps / args.threads
    results = {"sent": 0, "success": 0, "latencies": []}

    print(f"Starting benchmark: {args.qps} QPS total, {args.threads} threads, {args.duration}s...")

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(args.host, args.port, qps_per_thread, args.duration, results))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    total_time = args.duration
    actual_qps = results["sent"] / total_time
    success_rate = (results["success"] / results["sent"] * 100) if results["sent"] > 0 else 0
    avg_latency = (sum(results["latencies"]) / len(results["latencies"]) * 1000) if results["latencies"] else 0

    print("\nBenchmark results:")
    print(f"Queries sent: {results['sent']}")
    print(f"Successes:    {results['success']}")
    print(f"Actual QPS:   {actual_qps:.2f}")
    print(f"Success rate: {success_rate:.2f}%")
    print(f"Avg latency:  {avg_latency:.2f} ms")

if __name__ == "__main__":
    main()
