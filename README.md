analyseTCP
============
A utility for analysing tcpdump traces with regard to latency and loss. It supports analyses with a sender side trace alone as well as with both a sender and receiver side trace.

###Features with only a sender side trace

 * Detailed information about race

   * Packets sent (data/retransmissions,unique bytes) (SYN/FIN/RST)
   * Payload size and latency (ACK time) variance with customizable percentiles.
   * Retransmission count statistics (first/second/third...)
   * DupACK statistics


 * Loss estimation based on retransmissions
 * Saving latency (ACK time) to file for all packets (both aggregated and per stream)

###Features with sender and receiver side traces

 * True loss values based on the data that was received.
 * Calculating the amount of data received by initial transmit, retransmit and RDB.
 * Saving one-way delay variation for the received data. Handles clock skew drifting between sender and receiver hosts.

##Prerequisites: cmake pcap

###To build
    :~/analysetcp$ mkdir build
    :~/analysetcp$ cd build
    :~/analysetcp/build$ cmake ..
    :~/analysetcp/build$ make

##Example output
    :~/analysetcp/build$./analyseTCP -s 10.0.0.12 -r 10.0.0.22 -p 5000 -q 22000 -f sender.pcap -g receiver.pcap 
    
    STATS FOR CONN: 10.0.0.12:22000 -> 10.0.0.22:5000
      Duration: 602 seconds (0.167222 hours)
      Total packets sent                            :       6264
      Total data packets sent                       :       6259
      Total pure acks (no payload)                  :          2
      SYN/FIN/RST packets sent                      :      2/1/0
      Number of retransmissions                     :        272
      Number of packets with bundled segments       :          0
      Number of received acks                       :       6002
      Total bytes sent (payload)                    :     755760
      Number of unique bytes                        :     723240
      Number of retransmitted bytes                 :      32520
      Redundant bytes (bytes already sent)          :      32520 (4.30 %)
      Estimated loss rate based on retransmissions  :       4.34 %
    ---------------------------------------------------------------
    Receiver side loss stats:
      Bytes Lost (actual loss on receiver side)     :      31080
      Bytes Loss                                    :       4.11 %
      Ranges Lost (actual loss on receiver side)    :        259
      Ranges Loss                                   :       4.14 %
    ---------------------------------------------------------------
    Payload size stats:
      Average                                       :        120
      Minimum                                       :        120
      Maximum                                       :        360
    ---------------------------------------------------------------
    Latency stats:
      Minimum                                       :     150 ms
      Average                                       :     230 ms
      Maximum                                       :    1150 ms
    ===============================================================
    
    
    General info for entire dump:
      10.0.0.12:22000 -> 10.0.0.22:5000
      Filename: sender.pcap
      Sent Packet Count     : 6264
      Received Packet Count : 6005
      ACK Count             : 6002
      Sent Bytes Count      : 755760
      Max payload size      : 360
      Received Bytes        : 724680
      Packets Lost          : 259
      Packet Loss           : 4.13474 %
      Ranges Count          : 5990
      Ranges Sent           : 6262
      Ranges Lost           : 259

Loss stats
--------------

### Estimated loss rate based on retransmissions
This is the loss rate estimation based solely on the number of retransmissions. This only relies
on the sender side dump.
We here define loss rate as percentage of packets that have to be retransmitted using regular TCP schemes.

### Receiver side loss stats
These stats rely on both sender and receiver side dump and calculates the exact loss, that is, the bytes that
were sent and not received on the receiver side.

The Ranges Loss does not correspond directly to packets, as the packets may be split after being sent. With no segmentation offloading or segmentation in any nodes between the sender and receiver, the range count should correspond pretty well to the number of packets with unique data.


##Notes

* FIN segments with payload may be counted as two segments.
* Sender IP is required

* Negative packet loss values when analysing sender and receiver dumps

      The packet loss is calculated by (sent packet - received packets).
      When segmentation offloading is enabled on the sender, the sender dump may contain fewer
      packets than the receiver dump. Disabling any segmentation offload features is advised.

##Difference between analyseTCP and tcptrace

Total bytes sent (payload) and Number of retransmitted bytes might differ slightly (2 bytes) from tcptrace, but according to tshark analysetcp is correct:

####Example of how to calculate total sum of tcp payload bytes and retransmitted bytes
    tshark -r trace.dump -qz io,stat,0,"ip.addr==10.0.0.10 && tcp.srcport ==\
    15103","COUNT(tcp.analysis.retransmission)ip.addr==10.0.0.10 && tcp.srcport == 15102 &&\
    tcp.analysis.retransmission","SUM(tcp.len)tcp.len && ip.addr==10.0.0.10 && tcp.srcport ==\
    15102","SUM(tcp.len)tcp.len && ip.addr==10.0.0.10 && tcp.srcport == 15102 && tcp.analysis.retransmission"
