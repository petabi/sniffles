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
	sudo python3.4 setup.py install
	sudo python3.4 setup.py build
	echo "=========== Begin to tests ========="
	sudo python3.4 runtests.py
	echo "=========== Tested the sniffles ========="
	echo

fi
