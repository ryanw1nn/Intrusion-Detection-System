"""
Comprehensive tests for interface detection:
- InterfaceDetector
- Interface validation
- Auto-detection
- Error handling
"""

import unittest
from ids.interface_utils import (
    InterfaceInfo,
    InterfaceDetector,
    detect_and_validate_interface,
    list_interfaces
)
from unittest.mock import patch, MagicMock


class TestInterfaceInfo(unittest.TestCase):
    """Test InterfaceInfo class"""

    def test_creation(self):
        """Test creating InterfaceInfo"""
        iface = InterfaceInfo(
            name='eth0',
            ip_address='192.168.1.1',
            is_up=True,
            is_loopback=False
        )
        
        self.assertEqual(iface.name, 'eth0')
        self.assertEqual(iface.ip_address, '192.168.1.1')
        self.assertTrue(iface.is_up)
        self.assertFalse(iface.is_loopback)

    def test_repr(self):
        """Test string representation"""
        iface = InterfaceInfo(
            name='eth0',
            ip_address='192.168.1.1',
            is_up=True,
            is_loopback=False
        )
        
        repr_str = repr(iface)
        
        self.assertIn('eth0', repr_str)
        self.assertIn('192.168.1.1', repr_str)
        self.assertIn('UP', repr_str)


class TestInterfaceDetector(unittest.TestCase):
    """Test InterfaceDetector class"""

    def test_initialization(self):
        """Test detector initialization"""
        detector = InterfaceDetector()
        
        self.assertIsNotNone(detector.system)
        self.assertIsNotNone(detector.available_interfaces)
        self.assertIsInstance(detector.available_interfaces, list)

    def test_get_interface(self):
        """Test getting interface by name"""
        detector = InterfaceDetector()
        
        if len(detector.available_interfaces) > 0:
            first_iface = detector.available_interfaces[0]
            result = detector.get_interface(first_iface.name)
            
            self.assertIsNotNone(result)
            self.assertEqual(result.name, first_iface.name)

    def test_get_nonexistent_interface(self):
        """Test getting non-existent interface"""
        detector = InterfaceDetector()
        
        result = detector.get_interface('nonexistent_interface_xyz')
        
        self.assertIsNone(result)

    def test_get_available_interface_names(self):
        """Test getting list of interface names"""
        detector = InterfaceDetector()
        
        names = detector.get_available_interface_names()
        
        self.assertIsInstance(names, list)
        self.assertGreater(len(names), 0)  # Should have at least loopback

    def test_get_active_interfaces_exclude_loopback(self):
        """Test getting active interfaces without loopback"""
        detector = InterfaceDetector()
        
        active = detector.get_active_interfaces(include_loopback=False)
        
        self.assertIsInstance(active, list)
        # All should be non-loopback
        for iface in active:
            self.assertFalse(iface.is_loopback)

    def test_get_active_interfaces_include_loopback(self):
        """Test getting active interfaces with loopback"""
        detector = InterfaceDetector()
        
        active = detector.get_active_interfaces(include_loopback=True)
        
        self.assertIsInstance(active, list)
        self.assertGreater(len(active), 0)  # Should have at least loopback

    def test_suggest_interface(self):
        """Test interface suggestion"""
        detector = InterfaceDetector()
        
        suggested = detector.suggest_interface()
        
        # Should return an interface name or None
        self.assertTrue(suggested is None or isinstance(suggested, str))
        
        if suggested:
            # Suggested interface should exist
            iface = detector.get_interface(suggested)
            self.assertIsNotNone(iface)

    def test_validate_existing_interface(self):
        """Test validating an existing interface"""
        detector = InterfaceDetector()
        
        if len(detector.available_interfaces) > 0:
            first_iface = detector.available_interfaces[0]
            is_valid, message = detector.validate_interface(first_iface.name)
            
            self.assertIsInstance(is_valid, bool)
            self.assertIsInstance(message, str)

    def test_validate_nonexistent_interface(self):
        """Test validating non-existent interface"""
        detector = InterfaceDetector()
        
        is_valid, message = detector.validate_interface('nonexistent_xyz')
        
        self.assertFalse(is_valid)
        self.assertIn('not found', message.lower())


class TestLoopbackDetection(unittest.TestCase):
    """Test loopback interface detection"""

    def test_is_loopback_by_name(self):
        """Test loopback detection by interface name"""
        detector = InterfaceDetector()
        
        # Common loopback names
        self.assertTrue(detector._is_loopback_interface('lo', '127.0.0.1'))
        self.assertTrue(detector._is_loopback_interface('lo0', '127.0.0.1'))
        self.assertTrue(detector._is_loopback_interface('loopback', '127.0.0.1'))

    def test_is_loopback_by_ip(self):
        """Test loopback detection by IP address"""
        detector = InterfaceDetector()
        
        self.assertTrue(detector._is_loopback_interface('any', '127.0.0.1'))
        self.assertTrue(detector._is_loopback_interface('any', '127.0.0.5'))
        self.assertTrue(detector._is_loopback_interface('any', '::1'))

    def test_is_not_loopback(self):
        """Test non-loopback interfaces"""
        detector = InterfaceDetector()
        
        self.assertFalse(detector._is_loopback_interface('eth0', '192.168.1.1'))
        self.assertFalse(detector._is_loopback_interface('en0', '10.0.0.1'))


class TestInterfacePreference(unittest.TestCase):
    """Test interface preference sorting"""

    def test_sort_by_preference(self):
        """Test that ethernet is preferred over other types"""
        detector = InterfaceDetector()
        
        interfaces = [
            InterfaceInfo('wlan0', '192.168.1.5', True, False),
            InterfaceInfo('eth0', '192.168.1.2', True, False),
            InterfaceInfo('en0', '192.168.1.3', True, False)
        ]
        
        sorted_ifaces = detector._sort_by_preference(interfaces)
        
        # Ethernet interfaces (eth*, en*) should be first
        self.assertTrue(
            sorted_ifaces[0].name.startswith('eth') or 
            sorted_ifaces[0].name.startswith('en')
        )


class TestDetectAndValidate(unittest.TestCase):
    """Test detect_and_validate_interface function"""

    def test_auto_detect_when_no_interface_specified(self):
        """Test auto-detection when no interface specified"""
        interface, is_valid = detect_and_validate_interface(
            requested_interface=None,
            auto_detect=True,
            show_summary=False
        )
        
        # Should return an interface
        self.assertTrue(interface is None or isinstance(interface, str))
        self.assertIsInstance(is_valid, bool)

    def test_validate_specific_interface(self):
        """Test validating a specific interface"""
        detector = InterfaceDetector()
        
        if len(detector.available_interfaces) > 0:
            first_iface = detector.available_interfaces[0].name
            
            interface, is_valid = detect_and_validate_interface(
                requested_interface=first_iface,
                auto_detect=False,
                show_summary=False
            )
            
            self.assertEqual(interface, first_iface)

    def test_invalid_interface_with_auto_detect(self):
        """Test invalid interface falls back to auto-detect"""
        interface, is_valid = detect_and_validate_interface(
            requested_interface='nonexistent_xyz',
            auto_detect=True,
            show_summary=False
        )
        
        # Should auto-detect a valid interface
        if interface:
            self.assertTrue(is_valid)

    def test_invalid_interface_without_auto_detect(self):
        """Test invalid interface without auto-detect"""
        interface, is_valid = detect_and_validate_interface(
            requested_interface='nonexistent_xyz',
            auto_detect=False,
            show_summary=False
        )
        
        self.assertFalse(is_valid)


class TestListInterfaces(unittest.TestCase):
    """Test list_interfaces function"""

    def test_list_interfaces_runs(self):
        """Test that list_interfaces function runs without error"""
        # This should not raise an exception
        try:
            # Capture output by redirecting stdout temporarily
            import io
            import sys
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            
            list_interfaces()
            
            output = sys.stdout.getvalue()
            sys.stdout = old_stdout
            
            # Should have some output
            self.assertGreater(len(output), 0)
            
        except Exception as e:
            self.fail(f"list_interfaces() raised {e}")


class TestInterfaceErrorHandling(unittest.TestCase):
    """Test error handling in interface detection"""

    def test_handles_missing_scapy_gracefully(self):
        """Test that missing Scapy functions are handled"""
        # This tests that the code doesn't crash if Scapy fails
        detector = InterfaceDetector()
        
        # Should have created detector even if Scapy has issues
        self.assertIsNotNone(detector)
        self.assertIsInstance(detector.available_interfaces, list)

    def test_empty_interface_list_handled(self):
        """Test handling of empty interface list"""
        detector = InterfaceDetector()
        detector.available_interfaces = []
        
        # Should handle empty list gracefully
        suggested = detector.suggest_interface()
        self.assertIsNone(suggested)

    def test_interface_with_no_ip(self):
        """Test handling interface with no IP"""
        iface = InterfaceInfo('test0', '', True, False)
        
        self.assertEqual(iface.ip_address, '')
        self.assertTrue(iface.is_up)


class TestInterfaceStatusCheck(unittest.TestCase):
    """Test interface status checking"""

    def test_is_interface_up_for_loopback(self):
        """Test that loopback is detected as up"""
        detector = InterfaceDetector()
        
        # Try to find loopback
        for iface in detector.available_interfaces:
            if iface.is_loopback:
                # Loopback should be up
                self.assertTrue(iface.is_up)
                break


class TestInterfaceSummary(unittest.TestCase):
    """Test interface summary printing"""

    def test_print_interface_summary_runs(self):
        """Test that print_interface_summary doesn't crash"""
        detector = InterfaceDetector()
        
        try:
            import io
            import sys
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            
            detector.print_interface_summary()
            
            output = sys.stdout.getvalue()
            sys.stdout = old_stdout
            
            # Should have some output
            self.assertGreater(len(output), 0)
            self.assertIn('INTERFACE', output.upper())
            
        except Exception as e:
            self.fail(f"print_interface_summary() raised {e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)