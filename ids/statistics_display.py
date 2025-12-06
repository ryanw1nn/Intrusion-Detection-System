"""
Real-time statistics tracking and display for the IDS.

Provides:
- Real-time rate calculations (packets/sec, threats/sec)
- Top attackers tracking
- Color-coded terminal output
- Configurable update interval
- Thread-safe operation
"""

import threading
import time
import logging
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


# ANSI Color Codes
class Colors:
    """ ANSI color codes for terminal output """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    # Semantic Colors
    INFO = '\033[94m'       # Blue
    SUCCESS = '\033[92m'    # Green
    ALERT = '\033[93m'      # Yellow
    CRITICAL = '\033[91m'   # Red
    RESET = '\033[0m'


class StatisticsTracker:
    """
    Tracks IDS statistics over time for rate calculation

    Maintains sliding time windows for:
    - Packet processing events
    - Threat detection events
    - Source IP threat counts

    Thread-safe for concurrent access.
    """

    def __init__(self, window_size: int = 60):
        """
        Initialize the statistics tracker.

        Args:
            window_size: Time window in seconds for rate calculations
        """
        self.window_size = window_size
        
        # Deque for efficient sliding window
        self.packet_timestamps = deque(maxlen=10000) # Last 10k packets
        self.threat_timestamps = deque(maxlen=10000) # Last 10k threats

        # Track attackers (source IPs with threat counts)
        self.attacker_counts = defaultdict(int) # {ip: count}
        self.attack_last_seen = {}  # {ip: timestamp}

        # Track filtered packets
        self.filtered_timestamps = deque(maxlen=10000)

        # Thread safety
        self.lock = threading.Lock()

        logger.debug(f"StatisticsTracker initialized with {window_size}s window")

    def record_packet(self, timestamp: Optional[float] = None):
        """
        Record that a packet was processed.

        Args:
            timestamp: Event timestamp (default: current time)
        """
        if timestamp is None:
            timestamp = time.time()

        with self.lock:
            self.packet_timestamps.append(timestamp)

    def record_threat(self, source_ip: str, timestamp: Optional[float] = None):
        """
        Record that a threat was detected.

        Args:
            source_ip: Source IP address of the threat
            timestamp: Event timestamp (default: current time)
        """
        if timestamp is None:
            timestamp = time.time()

        with self.lock:
            self.threat_tiemstamps.append(timestamp)
            self.attacker_counts[source_ip] += 1
            self.attacker_last_seen[source_ip] = timestamp

    def record_filtered(self, timestamp: Optional[float] = None):
        """
        Record that a packet was filtered (whitelisted)

        Args:
            timestamp: Event timestamp (default: current time)
        """
        if timestamp is None:
            timestamp = time.time()

        with self.lock:
            self.filtered_timestamps.append(timestamp)
    
    def get_rate(self) -> Dict[str, float]:
        """
        Calculate current rates (per second).

        Returns:
            Dictionary with rates:
            - packets_per_sec: Packets processed per second
            - threats_per_sec: Threats detected per second
            - filtered_per_sec: Packets filtered per second
        """
        current_time = time.time()
        cutoff_time = current_time - self.window_size

        with self.lock:
            # Count events within the time window
            packets_in_window = sum(1 for ts in self.packet_timestamps if ts > cutoff_time)
            threats_in_window = sum(1 for ts in self.threat_timestamps if ts > cutoff_time)
            filtered_in_window = sum(1 for ts in self.filtered_timestamps if ts > cutoff_time)

            # Calculate rates (events per second)
            packets_per_sec = packets_in_window / self.window_size
            threats_per_sec = threats_in_window / self.window_size
            filtered_per_sec = filtered_in_window / self.window_size

        return {
            'packets_per_sec': packets_per_sec,
            'threats_per_sec': threats_per_sec,
            'filtered_per_sec': filtered_per_sec
        }

    def get_top_attackers(self, limit: int = 5) -> List[Tuple[str, int, float]]:
        """
        Get top N attackers by threat count

        Args:
            limit: Maximum number of attackers to return

        Returns:
            List of tuples (ip, threat_count, last_seen_timestamp)
            Sorted by threat count (descending)
        """
        with self.lock:
            # Filter out old attackers (not seen in 5 minutes)
            current_time = time.time()
            active_cutoff = current_time - 300  # 5 minutes
            
            active_attackers = [
                (ip, count, self.attacker_last_seen[ip])
                for ip, count in self.attacker_counts.items()
                if self.attacker_last_seen.get(ip, 0) > active_cutoff
            ]
            
            # Sort by threat count (descending)
            active_attackers.sort(key=lambda x: x[1], reverse=True)
            
            return active_attackers[:limit]
        
    def get_total_counts(self) -> Dict[str, int]:
        """
        Get total event counts.
        
        Returns:
            Dictionary with totals:
            - total_packets: Total packets processed
            - total_threats: Total threats detected
            - total_filtered: Total packets filtered
            - unique_attackers: Number of unique source IPs with threats
        """
        with self.lock:
            return {
                'total_packets': len(self.packet_timestamps),
                'total_threats': len(self.threat_timestamps),
                'total_filtered': len(self.filtered_timestamps),
                'unique_attackers': len(self.attacker_counts)
            }
        
    def reset(self):
        """ Reset all statistics """
        with self.lock:
            self.packet_timestamps.clear()
            self.threat_timestamps.clear()
            self.filtered_timestamps.clear()
            self.attacker_counts.clear()
            self.attacker_last_seen.clear()
        logger.info("Statistics tracker reset")

class StatisticsDisplay:
    """
    Displays real-time statistics to the console

    Runs in a seperate thread to update statistics periodically
    without blocking packet processing
    """
    
    def __init__(self, ids_instance, tracker: StatisticsTracker, config=None):
        """
        Initialize the statistics display.
        
        Args:
            ids_instance: Reference to IntrusionDetectionSystem instance
            tracker: StatisticsTracker instance
            config: ConfigLoader instance (optional)
        """
        self.ids = ids_instance
        self.tracker = tracker
        self.config = config
        
        # Get configuration
        self.enabled = self._get_config('performance.stats_display_enabled', True)
        self.update_interval = self._get_config('performance.stats_interval', 10)
        self.use_colors = self._get_config('performance.stats_use_colors', True)
        
        # Display thread
        self.display_thread = None
        self.running = False
        self.start_time = None
        
        logger.info(
            f"StatisticsDisplay initialized "
            f"(enabled={self.enabled}, interval={self.update_interval}s, colors={self.use_colors})"
        )

    def _get_config(self, path: str, default):
        """Get config value or use default."""
        if self.config:
            value = self.config.get(path, default)
            return value if value is not None else default
        return default
    
    def start(self):
        """Start the real-time statistics display."""
        if not self.enabled:
            logger.info("Statistics display disabled in config")
            return
        
        if self.running:
            logger.warning("Statistics display already running")
            return
        
        self.running = True
        self.start_time = time.time()
        self.display_thread = threading.Thread(target=self._display_loop, daemon=True)
        self.display_thread.start()
        logger.info("Statistics display started")

    def stop(self):
        """Stop the real-time statistics display."""
        if not self.running:
            return
        
        self.running = False
        
        if self.display_thread and self.display_thread.is_alive():
            self.display_thread.join(timeout=2)
        
        logger.info("Statistics display stopped")
    
    def _display_loop(self):
        """Main display loop (runs in separate thread)."""
        # Initial delay to let IDS start up
        time.sleep(self.update_interval)
        
        while self.running:
            try:
                # Render and print statistics
                stats_output = self._render_stats()
                print(stats_output, flush=True)
                
                # Wait for next update
                time.sleep(self.update_interval)
                
            except Exception as e:
                logger.error(f"Error in statistics display loop: {e}")
                time.sleep(self.update_interval)
    
    def _render_stats(self) -> str:
        """
        Render current statistics to a formatted string.
        
        Returns:
            Formatted statistics string with ANSI colors
        """
        # Get current statistics
        rates = self.tracker.get_rates()
        totals = self.tracker.get_total_counts()
        top_attackers = self.tracker.get_top_attackers(limit=5)
        
        # Get IDS-level statistics
        ids_stats = self.ids.get_statistics() if hasattr(self.ids, 'get_statistics') else {}
        
        # Calculate uptime
        uptime_seconds = int(time.time() - self.start_time) if self.start_time else 0
        uptime_str = self._format_uptime(uptime_seconds)
        
        # Build output string
        lines = []
        
        # Header
        lines.append(self._color_line("=" * 80, Colors.HEADER))
        lines.append(self._color_line(
            f"IDS Real-Time Statistics - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            Colors.HEADER + Colors.BOLD
        ))
        lines.append(self._color_line(f"Uptime: {uptime_str}", Colors.INFO))
        lines.append(self._color_line("=" * 80, Colors.HEADER))
        
        # Rates section
        lines.append(self._color_line("RATES (per second):", Colors.BOLD))
        lines.append(f"  Packets processed:  {self._color_value(rates['packets_per_sec'], 'rate')}")
        lines.append(f"  Threats detected:   {self._color_value(rates['threats_per_sec'], 'threat_rate')}")
        lines.append(f"  Packets filtered:   {self._color_value(rates['filtered_per_sec'], 'rate')}")
        
        # Totals section
        lines.append("")
        lines.append(self._color_line("TOTALS:", Colors.BOLD))
        lines.append(f"  Total packets:      {self._color_value(totals['total_packets'], 'count')}")
        lines.append(f"  Total threats:      {self._color_value(totals['total_threats'], 'threat_count')}")
        lines.append(f"  Total filtered:     {self._color_value(totals['total_filtered'], 'count')}")
        lines.append(f"  Unique attackers:   {self._color_value(totals['unique_attackers'], 'attacker_count')}")
        
        # Active flows
        if 'active_flows' in ids_stats:
            lines.append(f"  Active flows:       {self._color_value(ids_stats['active_flows'], 'count')}")
        
        # Top attackers section
        if top_attackers:
            lines.append("")
            lines.append(self._color_line("TOP ATTACKERS:", Colors.BOLD))
            for i, (ip, count, last_seen) in enumerate(top_attackers, 1):
                time_ago = int(time.time() - last_seen)
                time_str = f"{time_ago}s ago" if time_ago < 60 else f"{time_ago//60}m ago"
                lines.append(
                    f"  {i}. {self._color_value(ip, 'ip'):20s} "
                    f"{self._color_value(count, 'threat_count'):>6s} threats  "
                    f"({time_str})"
                )
        else:
            lines.append("")
            lines.append(self._color_line("TOP ATTACKERS: None", Colors.OKGREEN))
        
        lines.append(self._color_line("=" * 80, Colors.HEADER))
        lines.append("")
        
        return "\n".join(lines)
    
    def _format_uptime(self, seconds: int) -> str:
        """
        Format uptime in human-readable format.
        
        Args:
            seconds: Uptime in seconds
            
        Returns:
            Formatted string (e.g., "2h 15m 30s")
        """
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        
        parts = []
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0 or hours > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{secs}s")
        
        return " ".join(parts)
    
    def _color_line(self, text: str, color: str) -> str:
        """
        Apply color to entire line.
        
        Args:
            text: Text to colorize
            color: ANSI color code
            
        Returns:
            Colorized text (or plain text if colors disabled)
        """
        if not self.use_colors:
            return text
        return f"{color}{text}{Colors.RESET}"
    
    def _color_value(self, value, value_type: str) -> str:
        """
        Apply color to a value based on its type and magnitude.
        
        Args:
            value: Value to format and colorize
            value_type: Type of value (rate, threat_rate, count, etc.)
            
        Returns:
            Formatted and colorized string
        """
        if not self.use_colors:
            if isinstance(value, float):
                return f"{value:>6.2f}"
            else:
                return f"{value:>6}"
        
        # Format the value
        if isinstance(value, float):
            formatted = f"{value:>6.2f}"
        elif isinstance(value, str):
            formatted = value
        else:
            formatted = f"{value:>6}"
        
        # Choose color based on value type and magnitude
        if value_type == 'rate':
            # Packet rate: green = normal, yellow = high
            if isinstance(value, (int, float)):
                if value < 100:
                    color = Colors.OKGREEN
                elif value < 500:
                    color = Colors.WARNING
                else:
                    color = Colors.FAIL
            else:
                color = Colors.INFO
        
        elif value_type == 'threat_rate':
            # Threat rate: green = low, yellow = medium, red = high
            if isinstance(value, (int, float)):
                if value < 1:
                    color = Colors.OKGREEN
                elif value < 5:
                    color = Colors.WARNING
                else:
                    color = Colors.FAIL
            else:
                color = Colors.FAIL
        
        elif value_type == 'threat_count':
            # Threat count: green = low, yellow = medium, red = high
            if isinstance(value, (int, float)):
                if value < 10:
                    color = Colors.OKGREEN
                elif value < 50:
                    color = Colors.WARNING
                else:
                    color = Colors.FAIL
            else:
                color = Colors.FAIL
        
        elif value_type == 'attacker_count':
            # Attacker count: green = low, red = high
            if isinstance(value, (int, float)):
                if value < 5:
                    color = Colors.OKGREEN
                else:
                    color = Colors.FAIL
            else:
                color = Colors.INFO
        
        elif value_type == 'ip':
            # IP addresses: cyan
            color = Colors.OKCYAN
        
        else:
            # Default: blue
            color = Colors.INFO
        
        return f"{color}{formatted}{Colors.RESET}"
    
    def display_final_summary(self):
        """
        Display final summary statistics (called on shutdown).
        """
        print("\n")
        print(self._color_line("=" * 80, Colors.HEADER))
        print(self._color_line("FINAL IDS STATISTICS", Colors.HEADER + Colors.BOLD))
        print(self._color_line("=" * 80, Colors.HEADER))
        
        # Get final statistics
        totals = self.tracker.get_total_counts()
        top_attackers = self.tracker.get_top_attackers(limit=10)
        
        # Calculate uptime
        uptime_seconds = int(time.time() - self.start_time) if self.start_time else 0
        uptime_str = self._format_uptime(uptime_seconds)
        
        print(f"Total uptime: {uptime_str}")
        print(f"Packets processed: {totals['total_packets']}")
        print(f"Threats detected: {totals['total_threats']}")
        print(f"Packets filtered: {totals['total_filtered']}")
        print(f"Unique attackers: {totals['unique_attackers']}")
        
        if top_attackers:
            print("\nTop 10 Attackers:")
            for i, (ip, count, _) in enumerate(top_attackers, 1):
                print(f"  {i:2d}. {ip:20s} {count:>6} threats")
        
        print(self._color_line("=" * 80, Colors.HEADER))
        print("")