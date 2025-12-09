#!/usr/bin/env python3
"""
Standalone Interface Detection Test Script

Test the interface detection functionality without modifying your IDS installation.
This helps verify the fix will work on your system before applying it.

Usage:
    python3 test_interface_detection.py
"""

import sys
import platform
import subprocess
from typing import List, Optional


def get_interface_list() -> List[str]:
    """Get list of network interfaces using system commands."""
    system = platform.system()
    interfaces = []
    
    try:
        if system == "Linux":
            # Try ip command first (newer Linux)
            try:
                result = subprocess.run(
                    ['ip', 'link', 'show'],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ':' in line and not line.startswith(' '):
                            parts = line.split(':')
                            if len(parts) >= 2:
                                iface = parts[1].strip()
                                if iface:
                                    interfaces.append(iface)
                    return interfaces
            except FileNotFoundError:
                pass
        
        # Fallback to ifconfig (works on macOS, BSD, older Linux)
        result = subprocess.run(
            ['ifconfig'],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line and not line.startswith(' ') and not line.startswith('\t'):
                    parts = line.split(':')
                    if parts:
                        iface = parts[0].strip()
                        if iface and not iface.startswith('//'):
                            interfaces.append(iface)
        
    except Exception as e:
        print(f"Error getting interfaces: {e}")
    
    return interfaces


def check_interface_status(interface: str) -> tuple:
    """
    Check if an interface is UP and get its IP.
    
    Returns:
        (is_up: bool, ip_address: str, is_loopback: bool)
    """
    try:
        result = subprocess.run(
            ['ifconfig', interface],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        if result.returncode == 0:
            output = result.stdout.lower()
            
            # Check if UP
            is_up = 'up' in output or 'running' in output
            
            # Check if loopback
            is_loopback = 'loopback' in output or interface.lower() in ['lo', 'lo0']
            
            # Try to extract IP
            ip_address = ''
            for line in result.stdout.split('\n'):
                if 'inet ' in line and 'inet6' not in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'inet' and i + 1 < len(parts):
                            ip_address = parts[i + 1]
                            break
                    break
            
            return is_up, ip_address, is_loopback
        
    except Exception as e:
        print(f"    Error checking {interface}: {e}")
    
    return False, '', False


def suggest_interface(interfaces_data: List[tuple]) -> Optional[str]:
    """
    Suggest best interface for monitoring.
    
    Args:
        interfaces_data: List of (name, is_up, ip, is_loopback) tuples
    
    Returns:
        Suggested interface name
    """
    # Priority 1: Active non-loopback with IP
    for name, is_up, ip, is_loopback in interfaces_data:
        if is_up and not is_loopback and ip and ip != '0.0.0.0':
            # Prefer ethernet names
            if name.startswith('eth') or name.startswith('en'):
                return name
    
    # Priority 2: Any active non-loopback with IP
    for name, is_up, ip, is_loopback in interfaces_data:
        if is_up and not is_loopback and ip and ip != '0.0.0.0':
            return name
    
    # Priority 3: Active non-loopback
    for name, is_up, ip, is_loopback in interfaces_data:
        if is_up and not is_loopback:
            return name
    
    # Priority 4: Active loopback
    for name, is_up, ip, is_loopback in interfaces_data:
        if is_up and is_loopback:
            return name
    
    return None


def main():
    """Run interface detection test."""
    print("\n" + "="*70)
    print("INTERFACE DETECTION TEST")
    print("="*70)
    print(f"Platform: {platform.system()}")
    print(f"Python: {sys.version.split()[0]}")
    print("="*70 + "\n")
    
    # Get interfaces
    print("Detecting network interfaces...\n")
    interfaces = get_interface_list()
    
    if not interfaces:
        print("❌ ERROR: No network interfaces found!")
        print("\nThis could mean:")
        print("  1. No network hardware is present")
        print("  2. You need to run with sudo for full interface info")
        print("  3. 'ifconfig' command is not available")
        print("\nTry running: sudo python3 test_interface_detection.py")
        return 1
    
    print(f"Found {len(interfaces)} interface(s)\n")
    
    # Check each interface
    interfaces_data = []
    active_non_loopback = []
    active_loopback = []
    inactive = []
    
    for iface in interfaces:
        is_up, ip, is_loopback = check_interface_status(iface)
        interfaces_data.append((iface, is_up, ip, is_loopback))
        
        if is_up and not is_loopback:
            active_non_loopback.append((iface, ip))
        elif is_up and is_loopback:
            active_loopback.append((iface, ip))
        else:
            inactive.append(iface)
    
    # Display results
    if active_non_loopback:
        print("🟢 ACTIVE INTERFACES (Recommended for monitoring):")
        for iface, ip in active_non_loopback:
            print(f"   • {iface:15s} - {ip if ip else 'no IP'}")
        print()
    
    if active_loopback:
        print("🟡 LOOPBACK INTERFACES (Local traffic only):")
        for iface, ip in active_loopback:
            print(f"   • {iface:15s} - {ip if ip else 'no IP'}")
        print()
    
    if inactive:
        print("🔴 INACTIVE INTERFACES:")
        for iface in inactive:
            print(f"   • {iface:15s} - DOWN")
        print()
    
    # Suggest best interface
    suggested = suggest_interface(interfaces_data)
    
    if suggested:
        print("="*70)
        print("💡 RECOMMENDATION")
        print("="*70)
        print(f"Best interface for monitoring: {suggested}")
        print()
        
        # Find details
        for name, is_up, ip, is_loopback in interfaces_data:
            if name == suggested:
                if is_loopback:
                    print("⚠️  NOTE: This is a loopback interface")
                    print("   Only local traffic will be captured")
                    print("   Consider using a physical interface if available")
                else:
                    print("✓ This is a physical interface (good for network monitoring)")
                
                if ip:
                    print(f"✓ Has IP address: {ip}")
                print()
                break
        
        print("To use this interface with the IDS:")
        print(f"    sudo python3 -m ids.intrusion_detection_system -i {suggested}")
        print()
        print("Or update config.yaml:")
        print(f"    network:")
        print(f"      interface: \"{suggested}\"")
        print("="*70 + "\n")
    else:
        print("="*70)
        print("❌ WARNING: No suitable interface found")
        print("="*70)
        print("All interfaces are either DOWN or unavailable.")
        print("Please check your network configuration.")
        print("="*70 + "\n")
    
    # Test summary
    print("TEST RESULTS:")
    print(f"  Total interfaces found: {len(interfaces)}")
    print(f"  Active (non-loopback):  {len(active_non_loopback)}")
    print(f"  Active (loopback):      {len(active_loopback)}")
    print(f"  Inactive:               {len(inactive)}")
    print()
    
    if active_non_loopback:
        print("✅ PASS: Active network interface(s) found")
        print("   The interface detection fix will work correctly!")
    elif active_loopback:
        print("⚠️  PARTIAL: Only loopback interface(s) found")
        print("   IDS will work but only capture local traffic")
    else:
        print("❌ FAIL: No active interfaces found")
        print("   Check your network configuration before using IDS")
    
    print("\n" + "="*70 + "\n")
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)