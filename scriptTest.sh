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
	sudo python3.4 runtests.py
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
	echo "=========== End of verification ========="
	echo
fi
