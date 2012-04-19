all: filter_on
	echo 'Done!'
filter_on: filter_on.cpp 
	g++ filter_on.cpp pcap_errors.c -lpcap -o filter_on
