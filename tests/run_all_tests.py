"""
Comprehensive Test Runner for Network IDS

Runs all test modules and provides detailed results

Usage:
    python run_all_tests.py
    python run_all_tests.py --verbose
    python run_all_tests.py --module core_components
"""

import unittest
import sys
import os
import time
from io import StringIO

# Add parent directory to path so we can import IDS modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Test moduels
TEST_MODULES = [
    'test_core_components',
    'test_filtering',
    'test_alerting',
    'test_statistics',
    'test_config',
    'test_interface_detection',
]


class ColoredTextTestResult(unittest.TextTestResult):
    """Test result class with colored output"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.test_times = {}
    
    def startTest(self, test):
        super().startTest(test)
        self.test_times[test] = time.time()
    
    def addSuccess(self, test):
        super().addSuccess(test)
        elapsed = time.time() - self.test_times.get(test, 0)
        if self.showAll:
            self.stream.writeln(f" \033[92m✓ OK\033[0m ({elapsed:.3f}s)")
    
    def addError(self, test, err):
        super().addError(test, err)
        if self.showAll:
            self.stream.writeln(" \033[91m✗ ERROR\033[0m")
    
    def addFailure(self, test, err):
        super().addFailure(test, err)
        if self.showAll:
            self.stream.writeln(" \033[91m✗ FAIL\033[0m")
    
    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        if self.showAll:
            self.stream.writeln(f" \033[93m⊘ SKIP\033[0m: {reason}")

def run_module_tests(module_name, verbosity=2):
    """Run tests for a single module"""
    try:
        # Import the test module
        test_module = __import__(module_name)
        
        # Load tests from module
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(test_module)
        
        # Run tests
        runner = unittest.TextTestRunner(
            verbosity=verbosity,
            resultclass=ColoredTextTestResult
        )
        result = runner.run(suite)
        
        return result
    except ImportError as e:
        print(f"\033[91m✗ Failed to import {module_name}: {e}\033[0m")
        return None
    
def print_header(text):
    """Print a formatted header"""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70)

def print_summary(results):
    """Print test summary"""
    print_header("TEST SUMMARY")
    
    total_tests = 0
    total_failures = 0
    total_errors = 0
    total_skipped = 0
    total_time = 0
    
    for module_name, result, elapsed in results:
        if result:
            tests_run = result.testsRun
            failures = len(result.failures)
            errors = len(result.errors)
            skipped = len(result.skipped)
            
            total_tests += tests_run
            total_failures += failures
            total_errors += errors
            total_skipped += skipped
            total_time += elapsed
            
            # Status indicator
            if failures == 0 and errors == 0:
                status = "\033[92m✓ PASS\033[0m"
            else:
                status = "\033[91m✗ FAIL\033[0m"
            
            print(f"{status} {module_name:30s} "
                  f"{tests_run:3d} tests, "
                  f"{failures:2d} failures, "
                  f"{errors:2d} errors, "
                  f"{skipped:2d} skipped "
                  f"({elapsed:.2f}s)")
    
    print("\n" + "-"*70)
    print(f"Total: {total_tests} tests, "
          f"{total_failures} failures, "
          f"{total_errors} errors, "
          f"{total_skipped} skipped")
    print(f"Time: {total_time:.2f}s")
    
    # Overall result
    if total_failures == 0 and total_errors == 0:
        print("\n\033[92m✓ ALL TESTS PASSED\033[0m")
        return True
    else:
        print(f"\n\033[91m✗ {total_failures + total_errors} TESTS FAILED\033[0m")
        return False

def run_all_tests(verbosity=2, specific_module=None):
    """Run all test modules"""
    print_header("COMPREHENSIVE IDS TEST SUITE")
    print(f"Running tests with verbosity={verbosity}")
    
    if specific_module:
        print(f"Running only: {specific_module}")
        modules_to_run = [specific_module]
    else:
        modules_to_run = TEST_MODULES
    
    results = []
    
    for module_name in modules_to_run:
        print(f"\n\033[1m>>> Testing: {module_name}\033[0m")
        
        start_time = time.time()
        result = run_module_tests(module_name, verbosity)
        elapsed = time.time() - start_time
        
        results.append((module_name, result, elapsed))
    
    # Print summary
    all_passed = print_summary(results)
    
    return 0 if all_passed else 1

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Comprehensive test runner for Network IDS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all tests
  python run_all_tests.py
  
  # Run with minimal output
  python run_all_tests.py --quiet
  
  # Run specific module
  python run_all_tests.py --module core_components
  
  # List available modules
  python run_all_tests.py --list
        """
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output (show each test)'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Minimal output'
    )
    
    parser.add_argument(
        '--module', '-m',
        help='Run specific test module'
    )
    
    parser.add_argument(
        '--list', '-l',
        action='store_true',
        help='List available test modules'
    )
    
    args = parser.parse_args()
    
    # List modules
    if args.list:
        print("Available test modules:")
        for module in TEST_MODULES:
            print(f"  - {module}")
        return 0
    
    # Determine verbosity
    if args.quiet:
        verbosity = 0
    elif args.verbose:
        verbosity = 2
    else:
        verbosity = 1
    
    # Run tests
    try:
        return run_all_tests(verbosity, args.module)
    except KeyboardInterrupt:
        print("\n\n\033[93mTests interrupted by user\033[0m")
        return 130
    except Exception as e:
        print(f"\n\033[91mUnexpected error: {e}\033[0m")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
