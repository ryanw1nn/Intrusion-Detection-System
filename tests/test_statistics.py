"""
Comprehensive tests for statistics tracking and display:
- StatisticsTracker
- StatisticsDisplay
- Rate calculations
- Thread safety
"""

import unittest
from ids.statistics_display import StatisticsTracker, StatisticsDisplay, Colors
import time
import threading


class TestStatisticsTracker(unittest.TestCase):
    """Unit tests for StatisticsTracker"""

    def setUp(self):
        self.tracker = StatisticsTracker(window_size=10)

    def test_initialization(self):
        """Test tracker initialization"""
        self.assertIsNotNone(self.tracker.packet_timestamps)
        self.assertIsNotNone(self.tracker.threat_timestamps)
        self.assertIsNotNone(self.tracker.attacker_counts)
        self.assertEqual(self.tracker.window_size, 10)

    def test_record_packet(self):
        """Test recording packet events"""
        self.tracker.record_packet()
        self.tracker.record_packet()
        
        totals = self.tracker.get_total_counts()
        self.assertEqual(totals['total_packets'], 2)

    def test_record_threat(self):
        """Test recording threat events"""
        self.tracker.record_threat("192.168.1.100")
        self.tracker.record_threat("192.168.1.100")
        self.tracker.record_threat("192.168.1.101")
        
        totals = self.tracker.get_total_counts()
        self.assertEqual(totals['total_threats'], 3)
        self.assertEqual(totals['unique_attackers'], 2)

    def test_record_filtered(self):
        """Test recording filtered packet events"""
        self.tracker.record_filtered()
        self.tracker.record_filtered()
        
        totals = self.tracker.get_total_counts()
        self.assertEqual(totals['total_filtered'], 2)

    def test_get_rates(self):
        """Test rate calculation"""
        base_time = time.time()
        
        # Record 10 packets over 5 seconds = 2 pkt/sec
        for i in range(10):
            self.tracker.record_packet(base_time + i * 0.5)
        
        rates = self.tracker.get_rates()
        
        # Should calculate rate over window
        self.assertGreater(rates['packets_per_sec'], 0)
        self.assertIsInstance(rates['packets_per_sec'], float)

    def test_get_top_attackers(self):
        """Test top attackers calculation"""
        # Create attackers with different threat counts
        self.tracker.record_threat("192.168.1.100")
        self.tracker.record_threat("192.168.1.100")
        self.tracker.record_threat("192.168.1.100")
        
        self.tracker.record_threat("192.168.1.101")
        self.tracker.record_threat("192.168.1.101")
        
        self.tracker.record_threat("192.168.1.102")
        
        top_attackers = self.tracker.get_top_attackers(limit=3)
        
        # Should be sorted by threat count
        self.assertEqual(len(top_attackers), 3)
        self.assertEqual(top_attackers[0][0], "192.168.1.100")  # IP
        self.assertEqual(top_attackers[0][1], 3)                 # Count
        self.assertEqual(top_attackers[1][0], "192.168.1.101")
        self.assertEqual(top_attackers[1][1], 2)

    def test_top_attackers_return_format(self):
        """Test that top attackers returns correct tuple format"""
        self.tracker.record_threat("192.168.1.100")
        
        top_attackers = self.tracker.get_top_attackers(limit=1)
        
        self.assertEqual(len(top_attackers), 1)
        attacker = top_attackers[0]
        self.assertEqual(len(attacker), 3)  # (ip, count, timestamp)
        self.assertIsInstance(attacker[0], str)   # IP
        self.assertIsInstance(attacker[1], int)   # Count
        self.assertIsInstance(attacker[2], float) # Timestamp

    def test_sliding_window(self):
        """Test that old events are excluded from rate calculation"""
        tracker = StatisticsTracker(window_size=2)  # 2 second window
        
        base_time = time.time()
        
        # Record old events (outside window)
        tracker.record_packet(base_time - 10)
        tracker.record_packet(base_time - 10)
        
        # Record recent events (inside window)
        tracker.record_packet(base_time - 1)
        tracker.record_packet(base_time - 0.5)
        
        rates = tracker.get_rates()
        
        # Should only count the 2 recent packets
        self.assertAlmostEqual(rates['packets_per_sec'], 1.0, places=1)

    def test_top_attackers_excludes_old(self):
        """Test that inactive attackers are excluded"""
        current_time = time.time()
        
        # Recent attacker
        self.tracker.record_threat("192.168.1.100", current_time - 60)
        
        # Old attacker (more than 5 minutes ago)
        self.tracker.record_threat("192.168.1.101", current_time - 400)
        
        top_attackers = self.tracker.get_top_attackers(limit=5)
        
        # Should only include recent attacker
        self.assertEqual(len(top_attackers), 1)
        self.assertEqual(top_attackers[0][0], "192.168.1.100")

    def test_reset(self):
        """Test resetting statistics"""
        self.tracker.record_packet()
        self.tracker.record_threat("192.168.1.100")
        
        self.tracker.reset()
        
        totals = self.tracker.get_total_counts()
        self.assertEqual(totals['total_packets'], 0)
        self.assertEqual(totals['total_threats'], 0)
        self.assertEqual(totals['unique_attackers'], 0)

    def test_thread_safety(self):
        """Test that operations are thread-safe"""
        def record_packets():
            for _ in range(100):
                self.tracker.record_packet()
        
        def record_threats():
            for i in range(100):
                self.tracker.record_threat(f"192.168.1.{i % 10}")
        
        # Run operations in parallel
        threads = [
            threading.Thread(target=record_packets),
            threading.Thread(target=record_threats),
            threading.Thread(target=record_packets)
        ]
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        totals = self.tracker.get_total_counts()
        
        # Should have recorded all events
        self.assertEqual(totals['total_packets'], 200)
        self.assertEqual(totals['total_threats'], 100)

    def test_deque_max_length(self):
        """Test that deques have maximum length"""
        # Record many events
        for i in range(20000):
            self.tracker.record_packet()
        
        # Should be limited to 10000 (maxlen)
        self.assertEqual(len(self.tracker.packet_timestamps), 10000)


class TestStatisticsDisplay(unittest.TestCase):
    """Unit tests for StatisticsDisplay"""

    def setUp(self):
        # Create mock IDS instance
        class MockIDS:
            def get_statistics(self):
                return {
                    'active_flows': 42,
                    'queue_size': 10
                }
        
        self.mock_ids = MockIDS()
        self.tracker = StatisticsTracker()
        self.display = StatisticsDisplay(
            ids_instance=self.mock_ids,
            tracker=self.tracker,
            config=None
        )

    def test_initialization(self):
        """Test that display initializes correctly"""
        self.assertIsNotNone(self.display.tracker)
        self.assertIsNotNone(self.display.ids)
        self.assertEqual(self.display.update_interval, 10)  # Default
        self.assertTrue(self.display.use_colors)  # Default
        self.assertTrue(self.display.enabled)  # Default

    def test_render_stats_basic(self):
        """Test basic statistics rendering"""
        # Record some events
        self.tracker.record_packet()
        self.tracker.record_threat("192.168.1.100")
        
        self.display.start_time = time.time() - 60  # 1 minute uptime
        output = self.display._render_stats()
        
        # Check that output contains expected sections
        self.assertIn("IDS Real-Time Statistics", output)
        self.assertIn("RATES", output)
        self.assertIn("TOTALS", output)
        self.assertIn("TOP ATTACKERS", output)

    def test_render_stats_with_attackers(self):
        """Test rendering with top attackers"""
        # Record threats from multiple IPs
        for i in range(5):
            self.tracker.record_threat("192.168.1.100")
        for i in range(3):
            self.tracker.record_threat("192.168.1.101")
        
        self.display.start_time = time.time()
        output = self.display._render_stats()
        
        # Should show attackers
        self.assertIn("192.168.1.100", output)
        self.assertIn("192.168.1.101", output)

    def test_color_coding(self):
        """Test that color codes are applied correctly"""
        # With colors enabled
        self.display.use_colors = True
        output = self.display._color_value(100, 'threat_count')
        self.assertIn(Colors.FAIL, output)  # High threat count = red
        
        # With colors disabled
        self.display.use_colors = False
        output = self.display._color_value(100, 'threat_count')
        self.assertNotIn(Colors.FAIL, output)

    def test_uptime_formatting(self):
        """Test uptime formatting"""
        self.assertEqual(self.display._format_uptime(30), "30s")
        self.assertEqual(self.display._format_uptime(90), "1m 30s")
        self.assertEqual(self.display._format_uptime(3661), "1h 1m 1s")
        self.assertEqual(self.display._format_uptime(7200), "2h 0m 0s")

    def test_uptime_edge_cases(self):
        """Test uptime formatting edge cases"""
        self.assertEqual(self.display._format_uptime(0), "0s")
        self.assertEqual(self.display._format_uptime(59), "59s")
        self.assertEqual(self.display._format_uptime(60), "1m 0s")
        self.assertEqual(self.display._format_uptime(3600), "1h 0m 0s")

    def test_display_disabled_by_config(self):
        """Test that display respects config setting"""
        class MockConfig:
            def get(self, path, default):
                if path == 'performance.stats_display_enabled':
                    return False
                return default
        
        display = StatisticsDisplay(
            ids_instance=self.mock_ids,
            tracker=self.tracker,
            config=MockConfig()
        )
        
        self.assertFalse(display.enabled)

    def test_custom_update_interval(self):
        """Test custom update interval from config"""
        class MockConfig:
            def get(self, path, default):
                if path == 'performance.stats_interval':
                    return 5
                return default
        
        display = StatisticsDisplay(
            ids_instance=self.mock_ids,
            tracker=self.tracker,
            config=MockConfig()
        )
        
        self.assertEqual(display.update_interval, 5)

    def test_colors_can_be_disabled(self):
        """Test that colors can be disabled via config"""
        class MockConfig:
            def get(self, path, default):
                if path == 'performance.stats_use_colors':
                    return False
                return default
        
        display = StatisticsDisplay(
            ids_instance=self.mock_ids,
            tracker=self.tracker,
            config=MockConfig()
        )
        
        self.assertFalse(display.use_colors)

    def test_start_stop(self):
        """Test starting and stopping display"""
        self.display.start()
        self.assertTrue(self.display.running)
        
        time.sleep(0.1)  # Let thread start
        
        self.display.stop()
        self.assertFalse(self.display.running)

    def test_start_when_disabled(self):
        """Test that start does nothing when disabled"""
        self.display.enabled = False
        self.display.start()
        
        self.assertFalse(self.display.running)
        self.assertIsNone(self.display.display_thread)

    def test_color_value_for_different_types(self):
        """Test color value formatting for different value types"""
        # Rate values
        self.display.use_colors = True
        
        # Low rate (green)
        output = self.display._color_value(10, 'rate')
        self.assertIn(Colors.OKGREEN, output)
        
        # High rate (red)
        output = self.display._color_value(600, 'rate')
        self.assertIn(Colors.FAIL, output)
        
        # Threat rate
        output = self.display._color_value(0.5, 'threat_rate')
        self.assertIn(Colors.OKGREEN, output)
        
        output = self.display._color_value(10, 'threat_rate')
        self.assertIn(Colors.FAIL, output)


class TestColorsEnum(unittest.TestCase):
    """Test Colors class"""

    def test_color_codes_exist(self):
        """Test that all color codes are defined"""
        self.assertIsNotNone(Colors.HEADER)
        self.assertIsNotNone(Colors.OKBLUE)
        self.assertIsNotNone(Colors.OKGREEN)
        self.assertIsNotNone(Colors.WARNING)
        self.assertIsNotNone(Colors.FAIL)
        self.assertIsNotNone(Colors.RESET)

    def test_semantic_colors(self):
        """Test semantic color aliases"""
        self.assertIsNotNone(Colors.INFO)
        self.assertIsNotNone(Colors.SUCCESS)
        self.assertIsNotNone(Colors.ALERT)
        self.assertIsNotNone(Colors.CRITICAL)

    def test_color_codes_are_strings(self):
        """Test that color codes are strings"""
        self.assertIsInstance(Colors.HEADER, str)
        self.assertIsInstance(Colors.OKGREEN, str)
        self.assertIsInstance(Colors.FAIL, str)
        self.assertIsInstance(Colors.RESET, str)


class TestRateCalculations(unittest.TestCase):
    """Test rate calculation accuracy"""

    def test_packet_rate_calculation(self):
        """Test packet rate calculation accuracy"""
        tracker = StatisticsTracker(window_size=10)
        base_time = time.time()
        
        # Record 20 packets over 10 seconds = 2 pkt/sec
        for i in range(20):
            tracker.record_packet(base_time + i * 0.5)
        
        rates = tracker.get_rates()
        
        # Should be 2.0 packets per second
        self.assertAlmostEqual(rates['packets_per_sec'], 2.0, places=1)

    def test_threat_rate_calculation(self):
        """Test threat rate calculation accuracy"""
        tracker = StatisticsTracker(window_size=10)
        base_time = time.time()
        
        # Record 10 threats over 10 seconds = 1 threat/sec
        for i in range(10):
            tracker.record_threat("192.168.1.100", base_time + i * 1.0)
        
        rates = tracker.get_rates()
        
        # Should be 1.0 threats per second
        self.assertAlmostEqual(rates['threats_per_sec'], 1.0, places=1)

    def test_zero_rate_with_no_events(self):
        """Test that rate is zero with no events"""
        tracker = StatisticsTracker(window_size=10)
        
        rates = tracker.get_rates()
        
        self.assertEqual(rates['packets_per_sec'], 0.0)
        self.assertEqual(rates['threats_per_sec'], 0.0)

    def test_rate_calculation_with_partial_window(self):
        """Test rate calculation when window isn't full"""
        tracker = StatisticsTracker(window_size=10)
        base_time = time.time()
        
        # Record 5 packets over 5 seconds
        for i in range(5):
            tracker.record_packet(base_time + i * 1.0)
        
        rates = tracker.get_rates()
        
        # Should calculate rate over full window (10 seconds)
        self.assertAlmostEqual(rates['packets_per_sec'], 0.5, places=1)


if __name__ == "__main__":
    unittest.main(verbosity=2)