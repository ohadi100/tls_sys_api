#! /usr/bin/python3

import argparse
import unittest
import globals
from HtmlTestRunner import HTMLTestRunner


_TESTS_DIR_PATH = "tests"


def main():
	parser = argparse.ArgumentParser(description="TLS API box tester")
	
	parser.add_argument('lib_path', type=str, help="Path to TLS shared library to test")

	args = parser.parse_args()

	globals.TLS_LIB_PATH = args.lib_path

	loader = unittest.TestLoader()
	suites = loader.discover(_TESTS_DIR_PATH, pattern="test_*.py")

	#TODO: remove recent reports in reports dir
	runner = HTMLTestRunner(combine_reports=True, report_name="tlsapi_component_tests_report")
	runner.run(suites)


if __name__ == "__main__":
	main()
