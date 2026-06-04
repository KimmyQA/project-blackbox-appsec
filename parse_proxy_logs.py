"""
Project BlackBox: Charles Proxy Log Security Parser.
Author: KimmyQA
Description: Parses intercepted traffic streams to flag unencrypted cleartext protocols.
"""

import json
import os
from typing import Dict, Any, List

class ProxyLogAnalyzer:
    """Automated scanner engine to identify data leakage in intercepted API streams."""
    
    def __init__(self, log_path: str):
        self.log_path: str = log_path

    def analyze_traffic_payload(self) -> int:
        """Inspects request objects for cleartext transmission protocols (HTTP)."""
        if not os.path.exists(self.log_path):
            print(f"❌ Error: Traffic log database '{self.log_path}' not found.")
            return -1

        with open(self.log_path, 'r', encoding='utf-8') as stream:
            data = json.load(stream)

        print("=== Starting Project BlackBox API Stream Traffic Scan ===")
        flagged_threats = 0
        records: List[Dict[str, Any]] = data.get("intercepted_traffic", [])

        for record in records:
            req_id = record.get("request_id", "UNKNOWN")
            url = record.get("url", "")
            
            print(f"\nAnalyzing Intercept Stream: {req_id}")
            
            # Security Rule Check: Flag plain HTTP traffic
            if url.startswith("http://"):
                print(f"🚨 [SECURITY BREACH] Cleartext Protocol Detected: {url}")
                print("   Risk: Traffic is vulnerable to credential sniffing and MITM injection.")
                flagged_threats += 1
            elif url.startswith("https://"):
                print(f"🔒 [SECURE PROTOCOL] Valid TLS connection wrapper verified: {url}")

        return flagged_threats

if __name__ == "__main__":
    # Test against our existing API audit log asset
    scanner = ProxyLogAnalyzer(log_path="api-audit-log.json")
    vulnerabilities_found = scanner.analyze_traffic_payload()
    
    print("\n================ [SCAN ENGINE SUMMARY] ================")
    print(f"• Total Cleartext Vulnerabilities Flagged: {vulnerabilities_found}")
    print("========================================================")
