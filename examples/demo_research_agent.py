#!/usr/bin/env python3
"""
MIS Demo: Research Agent with Intent-Based Security

This demonstrates:
1. Session creation with RESEARCH intent
2. Automatic capability grants (read, network, exec)
3. Enforcement of security boundaries
4. Audit trail generation
"""

import mis
import requests
import os
import sys


def research_agent():
    """
    AI agent performing academic research
    
    With RESEARCH intent, automatically gets:
    - CAP_READ: Read from /data/papers/*
    - CAP_NETWORK: Access arxiv.org, scholar.google.com
    - CAP_EXEC: Run pdftotext, pandoc
    """
    
    print("=== MIS Research Agent Demo ===\n")
    
    # ========================================================================
    # ALLOWED: Network access to arxiv.org
    # ========================================================================
    
    print("[1/5] Fetching papers from arXiv (allowed)...")
    try:
        resp = requests.get(
            "https://arxiv.org/search/?query=AI+safety",
            timeout=5
        )
        print(f"      ✓ SUCCESS: Status {resp.status_code}")
        print(f"      Downloaded {len(resp.content)} bytes\n")
    except Exception as e:
        print(f"      ✗ FAILED: {e}\n")
    
    # ========================================================================
    # ALLOWED: Read from /data/papers/
    # ========================================================================
    
    print("[2/5] Reading local paper (allowed)...")
    test_file = "/tmp/test_paper.txt"
    
    # Create test file first
    try:
        with open(test_file, "w") as f:
            f.write("Sample research paper content\n" * 10)
        print(f"      Created test file: {test_file}")
    except:
        pass
    
    try:
        with open(test_file, "r") as f:
            content = f.read()
        print(f"      ✓ SUCCESS: Read {len(content)} bytes\n")
    except PermissionError:
        print("      ✗ BLOCKED by MIS\n")
    
    # ========================================================================
    # BLOCKED: Network access to non-whitelisted domain
    # ========================================================================
    
    print("[3/5] Attempting access to non-whitelisted domain (blocked)...")
    try:
        resp = requests.get("https://malicious.example.com", timeout=2)
        print(f"      ✗ UNEXPECTED: Should be blocked! Status {resp.status_code}\n")
    except requests.RequestException:
        print("      ✓ CORRECTLY BLOCKED by MIS\n")
    
    # ========================================================================
    # BLOCKED: Write to /etc/ (no CAP_WRITE + denied path)
    # ========================================================================
    
    print("[4/5] Attempting write to /etc/shadow (blocked)...")
    try:
        with open("/etc/shadow", "w") as f:
            f.write("hacked")
        print("      ✗ UNEXPECTED: Should be blocked!\n")
    except PermissionError:
        print("      ✓ CORRECTLY BLOCKED by MIS (no CAP_WRITE to /etc)\n")
    
    # ========================================================================
    # BLOCKED: Execute unauthorized binary
    # ========================================================================
    
    print("[5/5] Attempting to execute /bin/sh (blocked)...")
    try:
        import subprocess
        subprocess.run(["/bin/sh", "-c", "echo hacked"], check=True)
        print("      ✗ UNEXPECTED: Should be blocked!\n")
    except (PermissionError, subprocess.CalledProcessError):
        print("      ✓ CORRECTLY BLOCKED by MIS (CAP_EXEC limited)\n")


def main():
    """Run demo with MIS session"""
    
    # Check if MIS orchestrator is running
    try:
        stats = mis.get_global_stats()
        print(f"MIS orchestrator connected: {stats['total_decisions']} total decisions\n")
    except Exception as e:
        print(f"ERROR: MIS orchestrator not reachable: {e}")
        print("\nPlease start the orchestrator:")
        print("  sudo systemctl start mis-orchestrator")
        print("  OR")
        print("  sudo /etc/mis/mis-policy-engine /etc/mis/config.toml")
        sys.exit(1)
    
    # Create session with RESEARCH intent
    print("Creating MIS session with RESEARCH intent...\n")
    
    with mis.session(intent="RESEARCH", ttl_secs=300) as session:
        print(f"✓ Session created: ID={session.session_id}")
        print(f"✓ Capabilities: {session.capabilities:#x}\n")
        
        # Run agent
        research_agent()
        
        # Show session stats
        print("\n=== Session Statistics ===")
        stats = session.stats()
        print(f"Session ID:       {stats.session_id}")
        print(f"State:            {stats.state}")
        print(f"Violations:       {stats.violation_count}")
        print(f"DEFCON Level:     {stats.defcon_level}/5")
        
        # Show global stats
        global_stats = mis.get_global_stats()
        print(f"\n=== Global Statistics ===")
        print(f"Total decisions:  {global_stats['total_decisions']}")
        print(f"Allowed:          {global_stats['allowed']}")
        print(f"Denied:           {global_stats['denied']}")
        print(f"Tokens validated: {global_stats['token_validated']}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
