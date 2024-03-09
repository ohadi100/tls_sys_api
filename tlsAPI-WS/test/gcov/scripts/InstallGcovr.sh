#!/bin/bash

REQUIRED_GCORV_VERSION="4.2"

RES=$(echo `gcovr --version` | grep -c "gcovr $REQUIRED_GCORV_VERSION")

echo $RES
if [ $RES -eq 1 ]
then
	echo The correct gcovr version is installed - $REQUIRED_GCORV_VERSION.
else
	echo the wrong gcovr version is installed.
	echo calling pip install to fix the issue:
	sudo pip install gcovr
fi
