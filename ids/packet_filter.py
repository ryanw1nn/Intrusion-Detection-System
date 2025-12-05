"""
Packet filtering module for whitelist/blacklist management.

Supports:
- Individual IP addresses
- CIDR notation for network ranges (e.g., 192.168.1.0/24)
- Port filtering
- Both IPv4 and IPv6
"""

import ipaddress
import logging
from typing import List, Set, Optional
from scapy.all import IP, TCP, IPV6_ADDR_6TO4

logger = logging.getLogger(__name__)


class PacketFilter:
    """
    Filters packets based on whitelist/blacklist rules.

    Whitelisted traffic is never analyzed (trusted sources).
    Blacklisted traffic always triggers alerts (known bad actors).
    """

    def __init__(self, config=None):
        self.config = config
        
        # Parse whitelists
        self.whitelist_ips = self._parse_ip_list(
            self._get_config('filtering.whitelist', [])
        )
        
        # Parse blacklists
        self.blacklist_ips = self._parse_ip_list(
            self._get_config('filtering.blacklist', [])
        )
        
        # Port whitelists (ports to ignore completely)
        self.whitelist_ports = set(
            self._get_config('filtering.whitelist_ports', [])
        )
        
        # Statistics
        self.stats = {
            'total_packets_filtered': 0,
            'whitelisted_packets': 0,
            'blacklisted_packets': 0,
            'port_filtered_packets': 0
        }
        
        logger.info(
            f"PacketFilter initialized: "
            f"{len(self.whitelist_ips)} whitelist entries, "
            f"{len(self.blacklist_ips)} blacklist entries, "
            f"{len(self.whitelist_ports)} whitelisted ports"
        )
        
        # Log the actual rules for debugging
        if self.whitelist_ips:
            logger.info(f"Whitelisted IPs/networks: {[str(ip) for ip in self.whitelist_ips]}")
        if self.blacklist_ips:
            logger.info(f"Blacklisted IPs/networks: {[str(ip) for ip in self.blacklist_ips]}")
        if self.whitelist_ports:
            logger.info(f"Whitelisted ports: {sorted(self.whitelist_ports)}")
    
    def _get_config(self, path: str, default):
        """Get config value or use default."""
        if self.config:
            return self.config.get(path, default)
        return default
    
    def _parse_ip_list(self, ip_strings: List[str]) -> List:
        """
        Parse list of IP addresses/networks into ipaddress objects.
        
        Args:
            ip_strings: List of IP addresses or CIDR networks as strings
            
        Returns:
            List of ipaddress.IPv4Address, IPv4Network, IPv6Address, or IPv6Network objects
        """
        parsed = []
        
        for ip_str in ip_strings:
            if not ip_str or ip_str.startswith('#'):
                continue
                
            try:
                # Try parsing as network (CIDR notation)
                if '/' in ip_str:
                    network = ipaddress.ip_network(ip_str, strict=False)
                    parsed.append(network)
                    logger.debug(f"Parsed network: {network}")
                else:
                    # Parse as individual address
                    addr = ipaddress.ip_address(ip_str)
                    parsed.append(addr)
                    logger.debug(f"Parsed address: {addr}")
            except ValueError as e:
                logger.warning(f"Invalid IP/network '{ip_str}': {e}")
                continue
        
        return parsed

    def _extract_ips_from_packet(self, packet) -> tuple:
        """
        Extract source and destination IPs from packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Tuple of (src_ip, dst_ip) as ipaddress objects, or (None, None) if not IP packet
        """
        try:
            if IP in packet:
                src_ip = ipaddress.ip_address(packet[IP].src)
                dst_ip = ipaddress.ip_address(packet[IP].dst)
                return src_ip, dst_ip
            elif IPv6 in packet:
                src_ip = ipaddress.ip_address(packet[IPv6].src)
                dst_ip = ipaddress.ip_address(packet[IPv6].dst)
                return src_ip, dst_ip
        except Exception as e:
            logger.debug(f"Error extracting IPs: {e}")
        
        return None, None
    
    def _extract_ports_from_packet(self, packet) -> tuple:
        """
        Extract source and destination ports from packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Tuple of (src_port, dst_port), or (None, None) if no TCP layer
        """
        if TCP in packet:
            return packet[TCP].sport, packet[TCP].dport
        return None, None
    
    def _ip_in_list(self, ip_addr, ip_list: List) -> bool:
        """
        Check if an IP address matches any entry in the list.
        
        Supports both individual IPs and network ranges.
        
        Args:
            ip_addr: ipaddress.IPv4Address or IPv6Address object
            ip_list: List of IP addresses or networks
            
        Returns:
            True if IP matches any entry, False otherwise
        """
        if not ip_addr or not ip_list:
            return False
        
        for entry in ip_list:
            try:
                # Check if entry is a network (has subnet mask)
                if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                    if ip_addr in entry:
                        return True
                # Check if entry is an individual address
                elif isinstance(entry, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    if ip_addr == entry:
                        return True
            except Exception as e:
                logger.debug(f"Error comparing {ip_addr} with {entry}: {e}")
                continue
        
        return False

    def is_whitelisted(self, packet) -> bool:
        """
        Check if packet is whitelisted (should be ignored).

        A packet is whitelisted if:
        - Source OR destination IP is in whitelist
        - Source OR destination port is in whitelisted ports

        Args:
            packet: Scapy packet object

        Returns:
            True if packet should be ignored, False otherwise
        """
        # Check port whitelist first (faster)
        src_port, dst_port = self._extract_ports_from_packet(packet)
        if src_port in self.whitelist_ports or dst_port in self.whitelist_ports:
            self.stats['port_filtered_packets'] += 1
            self.stats['total_packets_filtered'] += 1
            logger.debug(f"Packet whitelisted by port: {src_port} or {dst_port}")
            return True
        
        # Check IP whitelist
        src_ip, dst_ip = self._extract_ips_from_packet(packet)
        if not src_ip or not dst_ip:
            return False
        
        if self._ip_in_list(src_ip, self.whitelist_ips) or \
            self._ip_in_list(dst_ip, self.whitelist_ips):
                self.stats['whitelisted_packets'] += 1
                self.stats['total_packets_filtered'] += 1
                logger.debug(f"Packet whitelisted by IP: {src_ip} or {dst_ip}")
                return True
        
        return False

    def is_blacklisted(self, packet) -> bool:
        """
        Check if packet is blacklisted (known bad actor).
        
        A packet is blacklisted if:
        - Source IP is in blacklist (we don't care about destination for blacklist)
        
        Args:
            packet: Scapy packet object
            
        Returns:
            True if packet is from blacklisted source, False otherwise
        """
        src_ip, dst_ip = self._extract_ips_from_packet(packet)
        if not src_ip:
            return False
        
        if self._ip_in_list(src_ip, self.blacklist_ips):
            self.stats['blacklisted_packets'] += 1
            logger.debug(f"Packet blacklisted: {src_ip}")
            return True
        
        return False
    
    def should_analyze(self, packet) -> tuple:
        """
        Determine if packet should be analyzed and if it's from a known bad actor.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Tuple of (should_analyze: bool, is_blacklisted: bool)
            - (False, False): Whitelisted, skip analysis
            - (True, False): Normal packet, analyze normally
            - (True, True): Blacklisted, analyze with heightened sensitivity
        """
        # Whitelisted packets are completely ignored
        if self.is_whitelisted(packet):
            return False, False
        
        # Blacklisted packets are analyzed with extra attention
        blacklisted = self.is_blacklisted(packet)
        
        return True, blacklisted

    def add_to_whitelist(self, ip_or_network: str) -> bool:
        """
        Dynamically add an IP or network to whitelist.
        
        Args:
            ip_or_network: IP address or CIDR network string
            
        Returns:
            True if added successfully, False otherwise
        """
        try:
            parsed = self._parse_ip_list([ip_or_network])
            if parsed:
                self.whitelist_ips.extend(parsed)
                logger.info(f"Added to whitelist: {ip_or_network}")
                return True
        except Exception as e:
            logger.error(f"Failed to add to whitelist: {e}")
        
        return False
    
    def add_to_blacklist(self, ip_or_network: str) -> bool:
        """
        Dynamically add an IP or network to blacklist.
        
        Args:
            ip_or_network: IP address or CIDR network string
            
        Returns:
            True if added successfully, False otherwise
        """
        try:
            parsed = self._parse_ip_list([ip_or_network])
            if parsed:
                self.blacklist_ips.extend(parsed)
                logger.info(f"Added to blacklist: {ip_or_network}")
                return True
        except Exception as e:
            logger.error(f"Failed to add to blacklist: {e}")
        
        return False
    
    def add_to_blacklist(self, ip_or_network: str) -> bool:
        """
        Dynamically add an IP or network to blacklist.
        
        Args:
            ip_or_network: IP address or CIDR network string
            
        Returns:
            True if added successfully, False otherwise
        """
        try:
            parsed = self._parse_ip_list([ip_or_network])
            if parsed:
                self.blacklist_ips.extend(parsed)
                logger.info(f"Added to blacklist: {ip_or_network}")
                return True
        except Exception as e:
            logger.error(f"Failed to add to blacklist: {e}")
        
        return False
    
    def remove_from_whitelist(self, ip_or_network: str) -> bool:
        """
        Remove an IP or network from whitelist.
        
        Args:
            ip_or_network: IP address or CIDR network string
            
        Returns:
            True if removed successfully, False otherwise
        """
        try:
            parsed = self._parse_ip_list([ip_or_network])
            if parsed:
                for item in parsed:
                    if item in self.whitelist_ips:
                        self.whitelist_ips.remove(item)
                        logger.info(f"Removed from whitelist: {ip_or_network}")
                        return True
        except Exception as e:
            logger.error(f"Failed to remove from whitelist: {e}")
        
        return False

    def remove_from_blacklist(self, ip_or_network: str) -> bool:
        """
        Remove an IP or network from blacklist.
        
        Args:
            ip_or_network: IP address or CIDR network string
            
        Returns:
            True if removed successfully, False otherwise
        """
        try:
            parsed = self._parse_ip_list([ip_or_network])
            if parsed:
                for item in parsed:
                    if item in self.blacklist_ips:
                        self.blacklist_ips.remove(item)
                        logger.info(f"Removed from blacklist: {ip_or_network}")
                        return True
        except Exception as e:
            logger.error(f"Failed to remove from blacklist: {e}")
        
        return False
        
    def get_statistics(self) -> dict:
        """
        Get filtering statistics.
        
        Returns:
            Dictionary with filtering statistics
        """
        return {
            **self.stats,
            'whitelist_entries': len(self.whitelist_ips),
            'blacklist_entries': len(self.blacklist_ips),
            'whitelisted_ports': len(self.whitelist_ports)
        }
    
    def reset_statistics(self):
        """Reset filtering statistics."""
        self.stats = {
            'total_packets_filtered': 0,
            'whitelisted_packets': 0,
            'blacklisted_packets': 0,
            'port_filtered_packets': 0
        }
        logger.info("Filter statistics reset")