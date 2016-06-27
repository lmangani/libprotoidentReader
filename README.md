# libprotoident Reader
Proof-of-Concept PCAP reader using libprotoident Deep Packet Inspection library

## Usage: PCAP file
```
./reader_dpi -i ./path/to/file.pcap
```

#### Output
```
libprotoident Reader 0.1 
Reading packets from ./path/to/file.pcap ...   [CTRL-C to stop]

DPI Statistics:
================

	TOTAL FLOWS: 		12
	TOTAL BYTES: 		160338
	TOTAL PACKETS: 		907
	UNKNOWN PACKETS: 	24
	DPI THROUGHPUT: 	907.08 K pps / 1.16 Gb/sec
	TOTAL TIME: 		0.001 sec

	Detected Protocols:
	---------
	RTP                 PKTS: 836       BYTES: 143652    
	SIP_UDP             PKTS: 38        BYTES: 16342     
	STUN                PKTS: 9         BYTES: 344     

```

## Usage: Live device
```
./reader_dpi -i eth0 -s 1000
```

#### Output
```
libprotoident Reader 0.1 
Reading packets from eth0 ... 	[CTRL-C to stop]

DPI Statistics:
================

	TOTAL FLOWS: 		17
	TOTAL BYTES: 		41273
	TOTAL PACKETS: 		1000
	WRONG PACKETS: 		889
	UNKNOWN PACKETS: 	6
	DPI THROUGHPUT: 	344.39 K pps / 108.44 Mb/sec
	TOTAL TIME: 		0.003 sec

	Detected Protocols:
	---------
	Unknown_UDP         PKTS: 12        BYTES: 504       
	Unsupported         PKTS: 6         BYTES: 0         
	HTTP                PKTS: 63        BYTES: 40238     
	No_Payload          PKTS: 12        BYTES: 0         
	DNS                 PKTS: 2         BYTES: 103       
	NetBIOS_UDP         PKTS: 6         BYTES: 300       
	Skype               PKTS: 4         BYTES: 128       
```

