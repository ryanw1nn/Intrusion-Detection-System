"""
Network interface detection and validation utilities.

Provides intelligent interface selection, validation, and user guidance
to prevent monitoring the wrong interface
"""

import logging
import platform
import subprocess
from typing import List, Optional, Tuple, Dict
from scapy.all import get_if_list, get_if_addr, conf

logger = logging.getLogger(__name__)

class InterfaceInfo:
    """ Information about a network interface. """
    
    def __init__(self, name: str, ip_address: str = "", is_up: bool = False,
                 is_loopback: bool = False, has_traffic: bool = False):
        self.name = name
        self.ip_address = ip_address
        self.is_up = is_up
        self.is_loopback = is_loopback
        self.has_traffic = has_traffic

    def __repr__(self):
        status = "UP" if self.is_up else "DOWN"
        type_str = "LOOPBACK" if self.is_loopback else "PHYSICAL"
        return (f"InterfaceInfo(name='{self.name}', ip='{self.ip_address}', "
                f"status={status}, type={type_str})")
    
class InterfaceDetector:
    """
    Detects and validates network interfaces.
    
    Provides intelligent interface selection for monitoring.
    """

    def __init__(self):
        self.system = platform.system()
        self.available_interfaces = self._get_all_interfaces()
        logger.debug(f"Detected {len(self.available_interfaces)} network interfaces")
    
    def _get_all_interfaces(self) -> List[InterfaceInfo]:
        """
        Get all available network interfaces with their details.
        
        Returns:
            List of InterfaceInfo objects
        """
        interfaces = []
        
        try:
            # Get interface names from Scapy
            interface_names = get_if_list()

            for name in interface_names:
                try:
                    # get IP address
                    ip_addr = get_if_addr(name)

                    # Determine if loopback
                    is_loopback = self._is_loopback_interface(name, ip_addr)
                    
                    # Check if interface is up
                    is_up = self._is_interface_up(name)
                    
                    interface = InterfaceInfo(
                        name=name,
                        ip_address=ip_addr,
                        is_up=is_up,
                        is_loopback=is_loopback
                    )
                    
                    interfaces.append(interface)
                    logger.debug(f"Found interface: {interface}")
                    
                except Exception as e:
                    logger.debug(f"Could not get details for interface {name}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Failed to enumerate interfaces: {e}")
        
        return interfaces
    
    def _is_loopback_interface(self, name: str, ip_address: str) -> bool:
        """
        Determine if an interface is a loopback interface.
        
        Args:
            name: Interface name
            ip_address: Interface IP address
            
        Returns:
            True if loopback, False otherwise
        """
        # Check by name
        loopback_names = ['lo', 'lo0', 'loopback']
        if name.lower() in loopback_names:
            return True
        
        # Check by IP address
        loopback_ips = ['127.0.0.1', '::1', '0.0.0.0']
        if ip_address in loopback_ips:
            return True
        
        # Check if IP starts with 127
        if ip_address.startswith('127.'):
            return True
        
        return False
    

    def _is_interface_up(self, name: str) -> bool:
        """
        Check if an interface is up and running.
        
        Args:
            name: Interface name
            
        Returns:
            True if interface is up, False otherwise
        """
        try:
            if self.system == "Linux":
                # Check /sys/class/net/INTERFACE/operstate
                try:
                    with open(f'/sys/class/net/{name}/operstate', 'r') as f:
                        state = f.read().strip()
                        return state == 'up'
                except FileNotFoundError:
                    # Fallback to ifconfig
                    pass
            
            # Use ifconfig as fallback for all systems
            try:
                result = subprocess.run(
                    ['ifconfig', name],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                
                if result.returncode == 0:
                    output = result.stdout.lower()
                    # Check for UP flag
                    if 'up' in output or 'running' in output:
                        # Also check it's not just 'loopback' or 'broadcast up'
                        if 'status: active' in output or 'inet ' in output or 'inet6 ' in output:
                            return True
                    return False
                
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            # If all else fails, assume it exists means it's usable
            return True
            
        except Exception as e:
            logger.debug(f"Could not determine status for {name}: {e}")
            return False
    

    def get_interface(self, name: str) -> Optional[InterfaceInfo]:
        """
        Get information about a specific interface.
        
        Args:
            name: Interface name
            
        Returns:
            InterfaceInfo object or None if not found
        """
        for interface in self.available_interfaces:
            if interface.name == name:
                return interface
        return None

    def validate_interface(self, name: str) -> Tuple[bool, str]:
        """
        Validate that an interface exists and is suitable for monitoring.
        
        Args:
            name: Interface name to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        # Check if interface exists
        interface = self.get_interface(name)
        
        if interface is None:
            available = self.get_available_interface_names()
            return (False, 
                    f"Interface '{name}' not found. Available interfaces: {', '.join(available)}")
        
        # Check if interface is up
        if not interface.is_up:
            return (False, 
                    f"Interface '{name}' is DOWN. Please bring it up or choose another interface.")
        
        # Warn if loopback (but allow it)
        if interface.is_loopback:
            logger.warning(
                f"Interface '{name}' is a loopback interface. "
                f"Only local traffic will be captured. "
                f"For network monitoring, consider using a physical interface."
            )
        
        return (True, f"Interface '{name}' is valid and UP")
    
    def get_available_interface_names(self) -> List[str]:
        """
        Get list of available interface names.
        
        Returns:
            List of interface names
        """
        return [iface.name for iface in self.available_interfaces]
    
    def get_active_interfaces(self, include_loopback: bool = False) -> List[InterfaceInfo]:
        """
        Get list of active (UP) interfaces.
        
        Args:
            include_loopback: Whether to include loopback interfaces
            
        Returns:
            List of InterfaceInfo objects
        """
        active = [iface for iface in self.available_interfaces if iface.is_up]
        
        if not include_loopback:
            active = [iface for iface in active if not iface.is_loopback]
        
        return active
    
    def suggest_interface(self) -> Optional[str]:
        """
        Intelligently suggest the best interface for monitoring.
        
        Selection priority:
        1. Active non-loopback interface with valid IP
        2. Active non-loopback interface
        3. Active loopback interface
        4. Any available interface
        
        Returns:
            Suggested interface name or None
        """
        # Priority 1: Active non-loopback with valid IP
        candidates = [
            iface for iface in self.available_interfaces
            if iface.is_up and not iface.is_loopback and 
            iface.ip_address and iface.ip_address != '0.0.0.0'
        ]
        
        if candidates:
            # Prefer interfaces with more typical names (eth, en, wlan)
            preferred = self._sort_by_preference(candidates)
            logger.info(f"Suggested interface: {preferred[0].name} (active, non-loopback, {preferred[0].ip_address})")
            return preferred[0].name
        
        # Priority 2: Active non-loopback
        candidates = [
            iface for iface in self.available_interfaces
            if iface.is_up and not iface.is_loopback
        ]
        
        if candidates:
            preferred = self._sort_by_preference(candidates)
            logger.info(f"Suggested interface: {preferred[0].name} (active, non-loopback)")
            return preferred[0].name
        
        # Priority 3: Active loopback
        candidates = [
            iface for iface in self.available_interfaces
            if iface.is_up and iface.is_loopback
        ]
        
        if candidates:
            logger.warning(f"Only loopback interface available: {candidates[0].name}")
            return candidates[0].name
        
        # Priority 4: Any interface
        if self.available_interfaces:
            logger.warning(f"No active interfaces found, using first available: {self.available_interfaces[0].name}")
            return self.available_interfaces[0].name
        
        # No interfaces at all
        logger.error("No network interfaces found!")
        return None
    
    def _sort_by_preference(self, interfaces: List[InterfaceInfo]) -> List[InterfaceInfo]:
        """
        Sort interfaces by preference for monitoring.
        
        Preference order:
        1. Ethernet (eth, en)
        2. WiFi (wlan, wifi)
        3. Others
        
        Args:
            interfaces: List of interfaces to sort
            
        Returns:
            Sorted list of interfaces
        """
        def preference_score(iface: InterfaceInfo) -> int:
            name = iface.name.lower()
            
            # Ethernet interfaces (highest priority)
            if name.startswith('eth') or name.startswith('en'):
                return 3
            
            # WiFi interfaces
            if name.startswith('wlan') or name.startswith('wl') or 'wifi' in name:
                return 2
            
            # Others
            return 1
        
        return sorted(interfaces, key=preference_score, reverse=True)
    
    def print_interface_summary(self):
        """Print a formatted summary of all interfaces."""
        print("\n" + "="*70)
        print("AVAILABLE NETWORK INTERFACES")
        print("="*70)
        
        if not self.available_interfaces:
            print("No network interfaces found!")
            return
        
        # Group by status
        active_non_loopback = [i for i in self.available_interfaces if i.is_up and not i.is_loopback]
        active_loopback = [i for i in self.available_interfaces if i.is_up and i.is_loopback]
        inactive = [i for i in self.available_interfaces if not i.is_up]
        
        if active_non_loopback:
            print("\n🟢 ACTIVE INTERFACES (Recommended for monitoring):")
            for iface in active_non_loopback:
                print(f"   • {iface.name:15s} - {iface.ip_address or 'no IP'}")
        
        if active_loopback:
            print("\n🟡 LOOPBACK INTERFACES (Local traffic only):")
            for iface in active_loopback:
                print(f"   • {iface.name:15s} - {iface.ip_address or 'no IP'}")
        
        if inactive:
            print("\n🔴 INACTIVE INTERFACES:")
            for iface in inactive:
                print(f"   • {iface.name:15s} - DOWN")
        
        # Show suggestion
        suggestion = self.suggest_interface()
        if suggestion:
            print(f"\n💡 RECOMMENDED: Use interface '{suggestion}'")
            print(f"   Run with: sudo python3 -m ids.intrusion_detection_system -i {suggestion}")
        
        print("="*70 + "\n")

def detect_and_validate_interface(
    requested_interface: Optional[str] = None,
    auto_detect: bool = True,
    show_summary: bool = False
) -> Tuple[str, bool]:
    """
    Detect and validate network interface for monitoring.
    
    This is the main entry point for interface detection.
    
    Args:
        requested_interface: User-specified interface name (or None for auto-detect)
        auto_detect: Whether to auto-detect if requested interface is invalid
        show_summary: Whether to print interface summary
        
    Returns:
        Tuple of (interface_name, is_valid)
        
    Example:
        >>> interface, is_valid = detect_and_validate_interface('eth0')
        >>> if is_valid:
        ...     start_monitoring(interface)
    """
    detector = InterfaceDetector()
    
    # Show summary if requested
    if show_summary:
        detector.print_interface_summary()
    
    # If interface specified, validate it
    if requested_interface:
        is_valid, message = detector.validate_interface(requested_interface)
        
        if is_valid:
            logger.info(message)
            return requested_interface, True
        else:
            logger.error(message)
            
            if not auto_detect:
                return requested_interface, False
            
            logger.warning("Attempting to auto-detect suitable interface...")
    
    # Auto-detect interface
    if auto_detect or requested_interface is None:
        suggested = detector.suggest_interface()
        
        if suggested:
            logger.info(f"Auto-detected interface: {suggested}")
            return suggested, True
        else:
            logger.error("Could not auto-detect a suitable interface")
            return "", False
    
    return requested_interface, False

def list_interfaces() -> None:
    """
    Print a detailed list of all available interfaces.
    
    Useful for troubleshooting and user guidance.
    """
    detector = InterfaceDetector()
    detector.print_interface_summary()



if __name__ == "__main__":
    # Test the interface detection
    logging.basicConfig(level=logging.INFO)
    
    print("\n" + "="*70)
    print("NETWORK INTERFACE DETECTION TEST")
    print("="*70 + "\n")
    
    # List all interfaces
    list_interfaces()
    
    # Test auto-detection
    print("\nTesting auto-detection:")
    interface, is_valid = detect_and_validate_interface()
    if is_valid:
        print(f"✓ Auto-detected interface: {interface}")
    else:
        print("✗ Auto-detection failed")
    
    # Test validation of specific interface
    print("\nTesting validation of 'lo0':")
    interface, is_valid = detect_and_validate_interface('lo0', auto_detect=False)
    if is_valid:
        print(f"✓ Interface 'lo0' is valid")
    else:
        print("✗ Interface 'lo0' is not valid or not found")
