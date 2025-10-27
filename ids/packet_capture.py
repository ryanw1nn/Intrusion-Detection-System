"""
Packet capture module for network traffic monitoring.
Captures TCP/IP packets from network interfaces and queues them for analysis
"""

from scapy.all import sniff, IP, TCP
import threading
import queue
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class PacketCapture:
    """
    Handles packet capture from network interfaces using Scapy.

    Uses a seperate thread for packet capture and a queue to buffer packets
    for processing by the main IDS system.
    """

    def __init__(self, queue_size: int = 1000):
        """
        Initialize the packet captuer system.

        Args:
            queue_size: Maximum number of packets to buffer (prevents memory exhaustion)
        """
        self.packet_queue = queue.Queue(maxsize=queue_size)
        self.stop_capture = threading.Event()
        self.capture_thread: Optional[threading.Thread] = None
        logger.info(f"PacketCapture initialized with queue size: {queue_size}")

    def packet_callback(self, packet):
        """
        Callback function invoked for each captured packet.
        Filters for TCP/IP packets and adds them to the processing queue

        Args:
            packet: Scapy packet object
        """
        if IP in packet and TCP in packet:
            try:
                self.packet_queue.put(packet)
            except queue.Full:
                logger.warning("Packet queue full - dropping packet")

    def start_capture(self, interface="eth0"):
        """
        Start capturing packets on the speciifed network interface.
        Launches capture in a seperate thread to avoid blocking.

        Args:
            interface: Network interface name (e.g. 'eth0', 'en0', 'lo0')
        """
        def capture_thread():
            try:
                logger.info(f"Starting packet capture on interface: {interface}")
                sniff(
                    iface=interface,
                    prn=self.packet_callback,
                    store=0, # don't store packets in memory
                    stop_filter=lambda _: self.stop_capture.is_set()
                )
                logger.info("Packet capture stopped")
            except Exception as e:
                logger.error(f"Packet capture error: {e}")

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        """
        Stop packet capture and clean up resources.
        Flushes remaining packets from the queue and waits for capture thread to finish.
        """
        logger.info("Stopping packet capture...")

        # Signal capture thread to stop
        self.stop_capture.set()

        # Flush remaining packets from queue
        flushed = 0
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
                flushed += 1
            except queue.Empty:
                break
        
        if flushed > 0:
            logger.info(f"Flushed {flushed} packets from queue")
        
        # Wait for capture thread to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
            if self.capture_thread.is_alive():
                logger.warning("Capture thread did not terminate gracefully")
        
        logger.info("Packet capture stopped successfully")
    
    def get_queue_size(self) -> int:
        """
        Get the current number of packets waiting in the queue.

        Returns:
            Number of packets in queue
        """
        return self.packet_queue.qsize()