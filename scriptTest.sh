#!/bin/sh
if [ "$1" = "install" ]; then
	clear
	echo "=========== Begin to install and build ========="
	sudo python3.4 setup.py install
	sudo python3.4 setup.py build
	echo "=========== Installed and built the sniffles ========="
	echo
elif [ "$1" = "test" ]; then
	clear
	echo "=========== Begin to install and build ========="
	sudo python3.4 setup.py build
	echo "=========== Begin to tests ========="
	python3.4 runtests.py
	echo "=========== Tested the sniffles ========="
	echo
elif [ "$1" = "pep8" ]; then
	clear
	echo "=========== Begin to verify code standard ========="
	echo
	echo "==== Verifying sniffles.py ===="
	pep8 sniffles/sniffles.py
	echo "==== Verified ===="
	echo
	echo "==== Verifying ruletrafficgenerator.py ===="
	pep8 sniffles/ruletrafficgenerator.py
	echo "==== Verified ===="
	echo
	echo "==== Verifying rulereader.py ===="
	pep8 sniffles/rulereader.py
	echo "==== Verified ===="
	echo
	echo "==== Verifying rule_traffic_generator.py ===="
	pep8 sniffles/test/test_rule_traffic_generator.py
	echo "==== Verified ===="
	echo
	echo "==== Verifying test_rule_reader.py ===="
	pep8 sniffles/test/test_rule_reader.py
	echo "==== Verified ===="
	echo
	echo "==== Verifying feature.py ===="
	pep8 sniffles/feature.py
	echo "==== Verified ===="
	echo
	echo "==== Verifying test_feature.py ===="
	pep8 sniffles/test/test_feature.py
	echo "==== Verified ===="
	echo
	echo "==== Verifying rule_formats.py ===="
	pep8 sniffles/rule_formats.py
	echo "==== Verified ===="
	echo
	echo "==== Verifying test_ruleformats.py ===="
	pep8 sniffles/test/test_ruleformat.py
	echo "==== Verified ===="
	echo
	echo "==== Verifying regex_generator.py ===="
	pep8 sniffles/regex_generator.py
	echo "==== Verified ===="
	echo
	echo "==== Verifying test_regex_generator.py ===="
	pep8 sniffles/test/test_regex_generator.py
	echo "==== Verified ===="
	echo
	echo "=========== End of verification ========="
	echo
fi
