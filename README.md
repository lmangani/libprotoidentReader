# libprotoident Reader
Proof-of-Concept PCAP reader using libprotoident Deep Packet Inspection library

## Usage
```
./reader_dpi ./path/to/file.pcap
```

## Output
```
Analyzing pcap /home/lorenzo/Downloads/testcapture_voip.pcap

Statistics:
===========
	TOTAL FLOWS: 		12
	TOTAL BYTES: 		160338
	TOTAL PACKETS: 		907
	UNKNOWN PACKETS: 	24
	DPI THROUGHPUT: 	907.08 K pps / 1.16 Gb/sec
	TOTAL TIME: 		0.001 sec

	Detected Protocols:
	---------
	    * RTP 	PKTS: 836 	BYTES: 143652 
	    * SIP_UDP 	PKTS: 38 	BYTES: 16342 
	    * STUN 	PKTS: 9 	BYTES: 344 

```
