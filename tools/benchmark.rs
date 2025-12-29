use std::net::UdpSocket;
use std::time::{Instant, Duration};
use std::sync::{Arc, Mutex};
use std::thread;

const QNAME: &str = "google.com";
const QTYPE: u16 = 1; // A record

fn main() {
    let target = "127.0.0.1:5053";
    let concurrency = 50;
    let duration = Duration::from_secs(10);

    println!("Benchmarking {} with {} threads for {:?}...", target, concurrency, duration);

    // Construct simple DNS query (Header + Question)
    let mut packet = Vec::new();
    // Transaction ID (random)
    packet.extend_from_slice(&[0x12, 0x34]);
    // Flags (Standard Query, Recursion Desired)
    packet.extend_from_slice(&[0x01, 0x00]);
    // Questions: 1
    packet.extend_from_slice(&[0x00, 0x01]);
    // Answer RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // Authority RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // Additional RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]);

    // QNAME: \x06google\x03com\x00
    for label in QNAME.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00);

    // QTYPE: A (1)
    packet.extend_from_slice(&u16::to_be_bytes(QTYPE));
    // QCLASS: IN (1)
    packet.extend_from_slice(&u16::to_be_bytes(1));

    let packet = Arc::new(packet);
    let total_requests = Arc::new(Mutex::new(0u64));
    let total_failures = Arc::new(Mutex::new(0u64));
    let latencies = Arc::new(Mutex::new(Vec::new()));

    let start = Instant::now();
    let mut handles = Vec::new();

    for _ in 0..concurrency {
        let packet = packet.clone();
        let target = target.to_string();
        let total_requests = total_requests.clone();
        let total_failures = total_failures.clone();
        let latencies = latencies.clone();

        handles.push(thread::spawn(move || {
            let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
            socket.set_read_timeout(Some(Duration::from_millis(1000))).unwrap();
            let mut buf = [0u8; 512];

            while start.elapsed() < duration {
                 let req_start = Instant::now();
                 if socket.send_to(&packet, &target).is_ok() {
                     if socket.recv_from(&mut buf).is_ok() {
                         let lat = req_start.elapsed();
                         let mut l = latencies.lock().unwrap();
                         if l.len() < 10000 { // Sample first 10k
                             l.push(lat.as_micros() as u64);
                         }
                         *total_requests.lock().unwrap() += 1;
                     } else {
                         *total_failures.lock().unwrap() += 1;
                     }
                 } else {
                     *total_failures.lock().unwrap() += 1;
                 }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let elapsed = start.elapsed();
    let requests = *total_requests.lock().unwrap();
    let failures = *total_failures.lock().unwrap();
    let lats = latencies.lock().unwrap();

    println!("--- Benchmark Results ---");
    println!("Total Requests: {}", requests);
    println!("Total Failures: {}", failures);
    println!("Duration: {:.2?}", elapsed);
    println!("QPS: {:.2}", requests as f64 / elapsed.as_secs_f64());

    if !lats.is_empty() {
        let mut sorted = lats.clone();
        sorted.sort();
        let p50 = sorted[sorted.len() / 2];
        let p95 = sorted[(sorted.len() as f64 * 0.95) as usize];
        let p99 = sorted[(sorted.len() as f64 * 0.99) as usize];
        println!("Latency (us) p50: {}, p95: {}, p99: {}", p50, p95, p99);
    }
}
