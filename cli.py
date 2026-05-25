#!/usr/bin/env python3
import argparse
import json
import sys
import time
from scanner import Scanner
from db import GraphDB

def main():
    parser = argparse.ArgumentParser(description='CGE - Passive Recon & Graph Mapper')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--cookies', help='Cookies string')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--format', '-f', choices=['json', 'txt'], default='txt')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed request info')
    parser.add_argument('--save-db', action='store_true', help='Save results to Neo4j')
    parser.add_argument('--load-scan', help='Load previous scan ID from Neo4j')
    args = parser.parse_args()

    if args.load_scan:
        db = GraphDB()
        data = db.load_scan(args.load_scan)
        if not data:
            print(f"Scan {args.load_scan} not found")
            sys.exit(1)
        results = data
        results['total_hosts'] = len(results['nodes'])
        results['total_requests'] = 0
    else:
        scanner = Scanner(args.domain, cookies=args.cookies, cli_mode=True)
        results = scanner.scan()
        if args.save_db:
            db = GraphDB()
            scan_id = args.domain.replace('.', '_') + "_" + str(int(time.time()))
            db.save_scan(scan_id, args.domain, results['nodes'], results['edges'], results['endpoints'], results['requests'])
            print(f"\n[+] Saved to Neo4j with ID: {scan_id}")

    if args.format == 'json':
        output = json.dumps(results, indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"[+] Results saved to {args.output}")
        else:
            print(output)
    else:
        print("\n" + "=" * 70)
        print(f"  CGE Scan Results: {args.domain}")
        print("=" * 70)

        print(f"\n📊 SUMMARY")
        print(f"   ├─ Hosts found: {results['total_hosts']}")
        print(f"   ├─ Connections: {len(results['edges'])}")
        print(f"   └─ Requests captured: {results['total_requests']}")

        print(f"\n🌐 DISCOVERED HOSTS")
        for node in results['nodes']:
            print(f"   • {node['id']}")

        if results['edges']:
            print(f"\n🔗 CONNECTIONS")
            for edge in results['edges']:
                print(f"   • {edge['source']} → {edge['target']} [{edge['method']}]")
                if args.verbose and edge['details']:
                    print(f"       └─ {edge['details']}")

        if results['endpoints']:
            print(f"\n📂 ENDPOINTS BY HOST")
            for host, endpoints in results['endpoints'].items():
                if endpoints:
                    print(f"\n   📍 {host}")
                    for ep in sorted(endpoints)[:20]:
                        method = ep.split(' ')[0] if ' ' in ep else 'GET'
                        path = ep.split(' ')[1] if ' ' in ep else ep
                        print(f"      ├─ [{method}] {path}")
                    if len(endpoints) > 20:
                        print(f"      └─ ... and {len(endpoints) - 20} more")

        if args.verbose and results['requests']:
            print(f"\n📡 SAMPLE REQUESTS (first 10)")
            for i, req_data in enumerate(results['requests'][:10]):
                req = req_data['request']
                print(f"\n   [{i+1}] {req['method']} {req['url']}")
                print(f"       Status: {req_data['response']['status_code']}")
                if req['body']:
                    body_preview = req['body'][:100].replace('\n', ' ')
                    print(f"       Body: {body_preview}...")

        print("\n" + "=" * 70)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(f"CGE Scan: {args.domain}\n")
                f.write(f"Hosts: {results['total_hosts']}\n")
                f.write(f"Connections: {len(results['edges'])}\n\n")
                for edge in results['edges']:
                    f.write(f"{edge['source']} -> {edge['target']} [{edge['method']}]\n")
            print(f"\n[+] Results saved to {args.output}")

if __name__ == '__main__':
    main()
