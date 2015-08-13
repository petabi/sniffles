Sniffles--Packet Capture Generator for IDS and Regular Expression Evaluation
============================================================================

Sniffles is a tool for creating packet captures that will test IDS
that use fixed patterns or regular expressions for detecting
suspicious behavior.  Sniffles works very simply.  It takes a set of
regular expressions or rules and randomly chooses one regular
expression or rule.  It then generates content based on that rule or
regular expression.  For fixed strings, this means adding the string
directly to the data (possibly with offsets or other options as per
Snort rules).  For regular expressions the process is somewhat more
complex.  The regular expression is converted to an NFA and a
random path is chosen through the NFA (from start to end).
The resulting data will match to the regular expression.
Finally, Sniffles can be set to full match or partial match.
With a full match, the packet data will
absolutely match to at least one rule or regular expression (Some
Snort options are not fully considered though).  A partial match will
erase the last character from a matching character sequence to a
sequence that should not match (may match to another rule though).
Matching rules should cause the most burden on an IDS.  Thus, it is
possible to determine how well the IDS handles worst case traffic.
Partial matching traffic will cause almost as much burden as matching
traffic.  Finally, Sniffles can also generate traffic that has
completely random data.  Such random data offers a best case scenario
as random data is very unlikely to match with any rules.  Thus, it can
be processed at maximum speed.  Thus, Sniffles allows the creation of
packet captures for best and worst case operation of IDS deep packet
inspection.

In additon to above, Sniffles also has the ability to create
evaluation packet captures.  There are two types of evaluation packet
captures.  The first evaluation packet capture will create exactly one
packet for each rule or regular expression, in sequence.  Thus it is
possible to test and see that each rule matches as expected.  The full
evaluation goes a step further and creates a packet for exvery
possible branch in a regular expression.  A single regular expression
could have thousands of possible branches.  This tests to ensure that
all possible branches of a regular expression are handled properly.
Evaluation packet captures should match all packets.  Any unmatched
packets most likely represent a failure of the IDS and need further
investigation.  Of course, there is always the possiblity that
Sniffles is not creating the correct packet for a given IDS, or
doesn't recognize a particular option for a rule.  Check the supported
rule features for more information.

Finally, Sniffles can also do a lot for generating random network
traffic.  By default, random traffic is TCP, UDP, or ICMP and
unidirectional. However, it can also generate TCP traffic with ACKs,
handshakes, and teardowns for each stream.
It will generate correct sequence numbers and checksums.
Further, MAC addresses can be set according to desired distributions,
and IP network addresses can be defined by Home and External address
spaces.  In addition, it is possible to simulate scans within a
traffic capture.

Install
-------

REQUIRES: Python 3.3+ and the SortedContainers module

Sniffles consists of the following files:
- rulereader.py: The parser for rules.
- ruletrafficgenerator.py: The tool for generating content streams.
- sniffles.py: The main program managing the process.
- sniffles_config.py: handles command line input and options for Sniffles.
- traffic_writer.py: Writes a packet into a pcap compatible file.
  Does not require libpcap.
- vendor_mac_list.py: Contains MAC Organisationally Unique
  Identifiers used for generating semi-realistic MAC addresses rather
  than just randomly mashed together octets.
- examples/vendor_mac_definition.txt: Optional file for defining the
  distribution of partial or full MAC addresses.
- pcre files for pcre (pcre_chartables.c pcre_compile.c pcre_globals.c
pcre_internal.h pcre_newline.c pcre_tables.c pcre.h pcrecomp.c pcreconf.py
ucp.h).
- nfa.py: for traversing NFA.
- regex_generator.py: The code for generating random regular expressions.
- rand_rule_gen.py, feature.py, and rule_formats.py: modules for generating
random rule sets.

To install:

1. Go to the Top-level directory.
2. Type `python3.x setup.py install`.
3. This will install the application to your system.

Install Notes:

1. This has not been tested with Windows nor has it been tested on Linux.  It has been tested on FreeBSD and Mac OS X.
2. Use `python3.x setup.py build` to build locally, then go to the library directory, find the lib and use `python3.4 -c "from sniffles import sniffles; sniffles.main()"` to run locally.

Supported Formats:
-----------------
- Snort: Snort alert rules (rule should begin with the Alert
  directive).  Content tags are recognized and parsed correctly. PCRE
  tags are likewise correctly parsed. HTTP tags are processed
  consecutively so they may not create the
  desired packet.  Content (and PCRE or HTTP content) can be modified
  by distance, within and offset.  A rule may use a flow control
  option, though only the direction of the data is derived from this.
  The nocase option is ignored and the case presented is used.  All
  other options are ignored.  The header values are parsed and a
  packet will be generated meeting those values.  If Home and External
  network address spaces are used then the correct space will be used
  for the respective $HOME_NET and $EXTERNAL_NET variables.  Example:


    `alert tcp $EXTERNAL_NET any -> $HOME_NET 8080 (msg:"SERVER-APACHE Apache Tomcat UNIX platform directory traversal"; flow:to_server; content:"/..|5C|/"; content:"/..|5C|/"; http_raw_uri;`

- Regular expressions: Raw regular expressions 1 to a line written as
  either abc or /abc/i.  Currently supports the options i s, and m.
  Other options are ignored.  Example:

    `/ab*c(d|e)f/i`

- Sniffles Rule Format described below.

Command Line Options:
--------------------

  - -a TCP Ack: Send a TCP acknowledgment for every data packet sent.
     Off by default.  Acknowledgement packets have no data by default.

  - -b Bidirectional data: Data will be generated in both directions
     of a TCP stream. ACKs will be turned on.  This feature is off
     by default.

  - -c Count: Number of streams to create.  Each stream will contain a
     minimum of 1 packet.  Packet will be between two end-points as
     defined by the rule or randomly chosen.  tcp_handshake,
     tcp_teardown, and packets_per_stream will increase the number of
     packets per stream.  Currently, data in a stream flows in only
     one direction.  If the -b option is used data should flow
     in both directions.  Also, Sniffles rules can designate data
     to flow in both directions.

  - -C Concurrent Flows: Number of flows that will be open at one
     time.  Best effort in that if there are fewer flows than
     the number of concurrent flows designated then all of the
     current flows will be used.  For example, if there are only
     1000 flows remaining, but the number of concurrent flows
     was set to 10000, still only 1000 flows will be written out
     at that time.  The default value is 1000.  If used with
     duration the -C flows will be maintained throughout the
     duration which will ultimately disregard any input from -c.
     Note, the purpose of this is to create a diverse pcap where
     packets from the same flows are spread out rather than right
     next to each other and to create the illusion of many
     concurrent flows.  In our tests, we have managed up to 2-3
     million concurrent flows before memory becomes an issue.
     Also, we should mention that different latencies can among
     streams can cause some flows to terminate ealier than others.

  - -d Rules Directory: path to directory containing rule files.
     Will read every enabled rule in all rules file in the directory.
     Assumes all rules end with extension .rules.  Use this option or
     -f, but not both.  The # symbol is used to deactivate (i.e.
     comment out) a rule.

  - -D Duration: Generate based on duration rather than on count.
     The duration is in seconds.  Keep in mind that the default
     latency between packets is an average of 1-200 microseconds.
     For low latencies, a large duration could result in millions
     of packets which could take a long time to build.

  - -e eval: Create just one packet for each rule in the rule-set.
     Ignores all other input except -f.  Each packet will have
     content matching the selected rule.

  - -E Full Eval: Create one packet for each viable path in a pcre rule
     in the rule set.  In other words ab(c|d)e would
     create two packets: abce and abde.  Ignores all other input
     except -f.

  - -f Rule File: read a single rule file as per the provided path and
     file name.

  - -F Config: Designate a config file for Sniffles options.  The
     config file is a way of fixing the parameters used for a run
     of Sniffles.

  - -g Timestamp: set the starting time for the pcap timestamp.
     This will be the number of seconds since 12/31/1969.
     Default is current time.

  - -h IP Home Prefixes: A list of IP Home Network Prefixes.  IP
     addresses meant to come from an internal address will use these
     prefixes.  Prefixes may desginate an entire 4 byte IPv4 address
     in xxx.xxx format.  For example: "10.192.168,172.16".

  - -H IP v6 Home Prefixes: Same as IPv4 Home Prefixes just for IPv6.
     Notable exceptions, the separator is a colon with two bytes
     represented between colons.

  - -i IPv6 percentage: Set this value between 1 and 100 to generate
     packets with IPv6.  This will determine the percentage of
     streams that will be IPv6.

  - -I Intensity of scan attack (i.e. packets per second.)

  - -l Content Length: Fix the Content length to the number of bytes
     designated. Less than one will set the length equal to the
     content generated by nfa, or a random number between 10 and 1410
     if headers are random too.  Will truncate or pad the packet as
     necessary.

  - -L Latency: Average latency in microsecond.  If not set a random
     average latency between 1 and 200 usecs is determined for each
     stream.  Thus, the packets for a given stream will have an average
     latency amount of time between each packet in the flow.

  - -m Full match: Fully match rules.  By default, generated content
     will only partially match rules, thus alerts should not be
     generated (not guaranteed though).

  - -M Allows the use of a MAC distribution to have a custom MAC
       addresses in the traffic.  By default, MAC addresses are
       randomly generated. More information about the MAC
       definition file can be found in the
       examples/mac_definition_file.txt.
       Note:  You can specify up to two MAC definition files
       in order to set different values dependent on source or
       destination MACs.  If you specify only one file, it will
       be used for either direction. If you use the following
       notation you can specify for specific directions.
       For example: 'path1:path2'. Path1 will be MAC definition
       file for source MACs and path2 will be the MAC definition
       file for destination MACs. You may also use a question
       mark (?) to designate one or the other as random as in:
       '?:path2' to have random source MACs but use the file for.

  - -o output file: designate the name of the output file.  By default,
     the file is named: sniffles.pcap.

  - -O Offset: Offset before starting a scan attack.  Also used when
     inserting multiple scans into the traffic.  This is the number
     of seconds before the scan will start.  If used with -R, this
     becomes the average number of seconds prior to start.

  - -p Packets-per-stream: Designate the number of
     content-bearing packets for a single stream.
     If a positive value is provided as an argument then exactly x
     (if x is the provided integer) content-bearing packets will
     appear for each stream.  If x is negative, then a random
     number of packets will appear for each stream (from 1 to abs(x))
     By default, this value is 1.

  - -P Target Port list: For a scan attack. Provide a comma-sep list of
     possible ports, or a single starting port.  Otherwise ports will
     be scanned at random.  If a single starting port is provided,
     then ports will be scanned in order from that point to 65535,
     after which it will roll back to the starting point.  If a list
     is provided, the ports in the list will be scanned round-robin.

  - -r Random: Generate random content rather than from the rules.  If
     rules are still provided, the rules are used in the generation of
     the headers.  Note: many features in the rules may overide certain
     aspects of the random generation.

  - -R Random scan Attacks: Will use the Offset to create scan attacks in
     the traffic, but will use the offset only as a median.  The
     offset is used to determine the amount of time between when a
     scan finishes and a new scan starts.

  - -s Scan Attack: followed by a comma-sep list of ipv4 addr indicating
     what ip address to target. Each IP range will create
     one scan attack.  The ranges should be like: 192.168.1.1 which
     would target exactly that one ip address while 192.168.1 would
     target a random ip addresses between 192.168.1.0 and 192.168.1.255.

  - -S Scan type: 1==Syn scan (default) 2 == Connection scan.

  - -t TCP Handshake: Include a TCP handshake in all TCPstreams.  Off by
     default.

  - -T TCP Teardown: Include a TCP teardown in all TCPstreams.  Off by
     default.

  - -v Verbosity: Increase the level of output messages.

  - -w write content: Write the content strings to a file called 'all.re'

  - -W Window: The window, or duration, in seconds of a scan attack.

  - -Z Reply Chance: chance that a scan will have a reply.
     In other words, chance the targer port is open
     (default 20%).


Examples:
---------

NOTE: all examples assume you have installed the sniffles package.

To generate a pcap from a single file of regular expressions with 10
streams where every packet matches a rule

  `sniffles -c 10 -f myre.re -m`

To generate a pcap from a single snort rule file where every packet
almost matches a rule

  `sniffles -c 10 -f myrules.rules`

To generate a pcap from multiple snort rule files in a single
directory where every packet matches a rule.

  `sniffles -c 10 -d myrulesdir -m`

To generate the same pcap as above, using the same rules, but with
random content (Content is random, headers will still follow the
rules--does not work with regex or Sniffles rules):

  `sniffles -c 10 -d myrulesdir -r`

To generate a pcap with 10 streams (1 packet each) and with random
data:

  `sniffles -c 10`

To generate a pcap with 10 streams, each stream with 5 packets, with
ACKs and handshake and teardown as well as a fixed length of 50 for
the data in each data-bearing packet:

  `sniffles -c 10 -p 5 -l 50 -t -T -a`

To generate a pcap with 20 random streams with a home network of
192.168.1-2.x:

  `sniffles -c 20 -h 192.168.1,192.168.2`

To generate a pcap with 20 random streams with a home network of
192.168.x.x for IPv4 and 2001:8888:8888 for IPv6 with 50% of traffic
IPv6:

  `sniffles -c 20 -h 192.168.1 -H 2001:8888:8888 -i 50`

To generate a 5 second packet capture of random packets with an
average lapse between packets of 100 microseconds:

  `sniffles -D 5 -L 100`

To generate a pcap that will create one packet matching each rule in a
rule file (or regex file) in sequence:

  `sniffles -f myrules.rules -e`

To generate a pcap that will create a packet for every possible branch
of a regex for each regex in a set of regex and then save that file to
a pcap named everything.pcap is as below.  However, this function
can run in exponential time if the regex has a large amount of
min-max couning so it may take a long time to run.  Further,
all other options except the two illustrated below are ignored.

  `sniffles -f myrules.rules -o everything.pcap -E`

To generate random traffic with a scan attack occuring 2 seconds in
and lasting for 2 seconds with 1000 scan packets per second and with
the entire capture a duration of 5 seconds and lapse time of 50us and
with starting port 80 (sequentially searching ports from 80):

  `sniffles -D 5 -O 2 -W 2 -I 1000 -L 50 -s 192.168.1.2 -P 80`

Similar to above, but will create multiple scan attacks, each with
duration of 1 second, and an average offset between attacks of 2
seconds.  Further, only scans the designate ports.  Also targets IP
address in range 192.168.1.0-255 randomly.

  `sniffles -D 8 -O 2 -W 1 -I 10 -L 50 -s 192.168.1 -P 80,8080,8000,8001`


Sniffles Rule Format:
---------------------

Sniffles supports several rule formats.  First, Sniffles can parse Snort
rules, and regular expressions (at one per line).
In addition to this, Sniffles also has its own rule format that
can be used to explicitly control traffic.  This is done through the use
of xml files that will describe the traffic.  When this format is used
the other options for Sniffles may be irrelevant.  Example rule files can
be found in the examples directory.  These rule files are used simply
by designating the rule file with the -f option (i.e. sniffles -f rules.xml)

The Sniffles rule format is as follows:
```xml
<?xml version="1.0" encoding="utf-8"?>
<petabi_rules>
  <rule name="test" >
    <traffic_stream proto="tcp" src="any" dst="any" sport="any"
    dport="any" handshake="True" teardown="True" synch="True" ip="4">
      <pkt dir="to server" content="/abc/i" fragment="0" times="1" />
      <pkt dir="to client" content="/def/i" fragment="0" times="1" />
    </traffic_stream>
    <traffic_stream proto="tcp" src="any" dst="any" sport="any"
    dport="any" handshake="True" teardown="True" synch="True">
      <pkt dir="to server" content="/abc/i" fragment="0" times="1" />
      <pkt dir="to client" content="/def/i" fragment="0" times="1" />
    </traffic_stream>
  </rule>
</petabi_rules>
```

In detail, the tags work as follows:

- `<petabi_rules> </petabi_rules>`:  This defines all of the rules for this
  rules file.  There should only be one set of these tags opening and
  closing all of the designated traffic streams.
    - `<rule > </rule>`: Designates a single rule.  A single rule can generate
      an arbitrary number of traffic streams or packets.  May have any number
      of rules in a single file.
        - Options:
            - name: The name for this rule.  Mostly for documentation, no real
              function.
        - `<traffic_stream> </traffic_stream>`: A traffic stream defines traffic
          between two endpoints.  All pkts designated within a single traffic
          stream will share the same endpoints.  Any number of traffic streams
          can be designatted for a given rule.  Different traffic streams within
          the same rule may have different end-points or not depending on the
          settings below.
            - Options:
                - typets: Specify which type of traffic stream we will use to
                  generate packet. Currently, we have Standard and ScanAttack.
                - scantype: 1==Syn scan (default) 2 == Connection scan.
                  It is used with ScanAttack.
                - target: Specify the target ip address for Scan Attack.
                - targetports: For a scan attack. Provide a comma-sep list of
                  possible ports, or a single starting port.  Otherwise ports will
                  be scanned at random.  If a single starting port is provided,
                  then ports will be scanned in order from that point to 65535,
                  after which it will roll back to the starting point. This option
                  is used together with typets being 'ScanAttack'
                - srcport: Specify the source port for Scan Attack.  Random by default
                - duration: The window, or duration, in seconds of a scan attack
                  if typets is 'ScanAttack'
                - intensity: Intensity of scan attack if typets is 'ScanAttack'.
                - offset: Offset before starting a scan attack.  Also used when
                  inserting multiple scans into the traffic.
                - replychance: Chance that a scan will have a reply.
                  In other words, chance the targer port is open
                  (default 20%). It is used with ScanAttack.
                - proto: Designates the protocol of this traffic stream.
                  Should be TCP or or UDP or ICMP (not tested).
                - src: Source IP address.  May be an address in xxx.xxx.xxx.xxx
                  format, $EXTERNAL_NET (for an external address--assumes a home
                  network has been designated), $HOME_NET, or any (randomly
                  selects IP address).
                - dst: Destination IP Address.  Same as Source IP Address.
                - sport: Source port (assumes TCP or UDP).  Can use snort port
                  formatting which can be a comma separated list in brackets
                  (i.e. [80,88,89]), a range (i.e. [10:1000]), or any
                  (i.e. random pick from 0-65535).
                - dport: Destination Port as per sport.
                - handshake: Will generate a TCP Handshake at the start of the
                  stream.  If excluded, there will be no handshake.  Valid values
                  are true or false.  Default is false.
                - latency: set the average latency between packets (in microseconds).
                - teardown: Will close the stream when all traffic has been sent
                  by appending the TCP teardown at the end of the traffic stream.
                  Valid values are true or false.  Default is false.
                - synch: Traffic streams are synchronous or not.  When true, one
                  traffic stream must finish prior to the next traffic stream
                  starting.  When false, all contiguous streams that are false
                  (i.e. asynchronous) will execute at the same time.
                - tcp_overlap: The default value is false. When true, from the
                  second packet will be appended one extra content and the tcp
                  sequence number will be reduced by one to simulate the tcp
                  overlapping sequence number.
                - ipv: Designate IPv4 or IPv6.  Valid options are 4, or 6.
                  Default is 4.
                - out_of_order: Randomly have packets arrive out-of-order.
                  Note, this only works with packets that use the 'times'
                  option.  Further, this option should also be used with ack so
                  that the proper duplicate acks will appear in the traffic trace.
                  Valid values are true or false.  Default is false.
                - out_of_order_prob: Set the probability that packets will arrive
                  out-of-order.  For example, 10 would mean that there is a 10%
                  chance for each packet to arrive out of order.  Out-of-order
                  packets arrive after all of the in-order packets.
                  Further, they are randomly mixed as well.  Thus,
                  if the first packets 2 and 5 of 10 packets are determined to be
                  out of order, they will arrive last of the 10 packets
                  (slots 9 and 10) and will be in an arbitrary order
                  (i.e. 5 may come before 2 or vice versa).  The value
                  for this must be between 1 and 99.  Default is 50.
                - packet_loss: Randomly have packets be dropped (i.e. not arrive).
                  This only works with the 'times' option.  Further, this option
                  should also be used with the ack option set to true so that
                  duplicate acks will appear in the traffic trace.  Valid values
                  are 1 to 99 representing the chance that a packet will be dropped.
                  Note, the packet drop only happens on data-bearing packets, not
                  on the acks.
            - `<pkt > </pkt>`:  This directive designates either an individual
              packet or a series of packets.  The times feature can be used to have
              one <pkt> </pkt> directive generate several packets.  Otherwise, it is
              necessary to explicitly designate each packet in each direction.
                - Options:
                    - dir: The direction of the packet.  Valid values are to server
                      or to client.  The inititial src IP is considered the client,
                      and the intitial dst IP the server.  Thus 'to server' sends a
                      packet from client to server and 'to client' send a packet
                      from server to client.  Default is to server.
                    - content: Regular expression designating the content for this
                      packet.  Size of the packet will depend on the regular
                      expression.
                    - fragment: Whether or not to fragment this packet.
                      Only works with ipv4.  Should have a value larger than 2.
                      Will create as many fragments as are valid or as designated
                      (whichever is smaller).  Default value is 0 meaning no
                      fragments.
                    - ack: Send an ack to this packet or not.  Valid values are
                      true or false.  Default is false.
                    - split: Split the content among the designated number of
                      packets.  By default all content is sent in a single
                      packet (fragments are small exception to this rule).
                    - times: Send this packet x times.  Default value is 1,
                      a positive value will send exactly x packets (possibly
                      with acks if ack is true), while a negative number will
                      send a random number of packets between 1 and abs(-x).
                    - ttl: set time to live value for packet. By default,
                      sniffles will generate random TTL value.
                    - ttl_expiry: simulate the ttl expiry attack by breaking
                      packets into multiple packet with one malicious packet
                      between two good packet. By default, the value is 0
                      (No malicious packet). If the value is nonzero, it will
                      insert malicious packet with this ttl equals ttl_expiry
                      value. If the ttl value is set, good packet will be set
                      with new ttl value

Final Notes: The new rule format is just a beginning and may contain problems.
Please alert me of any inconsitencies or errors.  Further, the intent is to
exapand the options to provide more and more functionality as needed.
Please contact me with desired features.  Finally, this product is
provided as is.  There is no guaranttee of functionality or
accuracy.  Feel free to branch this project to meet your own needs.

Credits:
--------

This application has been brought to you by Petabi, Inc. where we make
Reliable, Realistic, and Real-fast security solutions.

Authors:

- Victor C. Valgenti
- Min Sik Kim
- Tu Le

New Features:
-------------

- 11/21/2014: Version 1.4.0 Added traffic splitting and traffobot for
   bi-directional traffic generation.  Fixed bug where an exception was
   thrown when the amount of traffic generated could fit in a single
   traffic write call. Reformatted and enabled usage.  Finally, added
   unit tests for traffobot and XML parsing.

- 02/03/2015: Version 2.0.  Completely rewrote how streams work in order to reduce
   memory requirments when generating large streams using special rules.  Currently,
   can handle around 2-3 million concurrent flows before things bog down.  I have
   added some features to try and help for when creating large flows.  First,
   generate with somthing like a concurrency of 2-3 million flows.  Also, do not use
   teardown for these flows.  A fraction of the flows will last from the beginning
   through to the end of the capture while the remainder will be closed out every
   batch period.  I will work on making this more efficient, but managing
   all of the complex options in Sniffles now cannot really be done cheaply in
   memory.  The only other solution is to get a beefier machine with more RAM.
   This version also contains a variety of fixes.

- 02/11/2015: Added probability to out-of-order packets to allow the frequency
   of out of order packets to be tuned.

- 03/05/2015: Changed TCP teardown to standard teardown sequence.
   Now allow content to be spread across multiple packets without using fragments.

- 04/09/2015: Fixed scan traffic, it was partially broken during one of the previous
   changes.  The pcap starting timestamp now defaults to the current time and can
   be set with the -g option.  Finally, the 3rd packet in the 3-way tcp handshake
   will now be data-bearing if the client is to send data first.

- 05/22/2015: Rewrote rule-parsing to simplify the ability to extend rule
   the rule parser to accomodate more formats.  Embedded nfa traversal and
   pcre directly into sniffles.  Cleaned up code and prepared it for the
   public.

- 05/27/2015: Updated documentation, merged in pcre libraries and
   nfa construction to make sniffles a self-contained package.
   Added the Regex Generator and the Random Rule Generator as
   a part of the Sniffles package.  Updated version to 3.0.0
   and published to github.

- 08/12/2015: Implemented a large number of bug fixes and new
   features.  Fundamentally changed how streams and flows are
   handled to allow for improved extensibility.  Added per
   flow latency.  Updated documentation. 

Regular Expression Generator
============================

This is a simple regular expression generator.
It creates regular expressions either completely randomly, or
based on a serires of distributions.
The controls that can be placed on how the regular expressions are
generated are structural rather than contextual.  In other words,
there is no effort to make certain string tokens appear in
the generated regular expressions.  However, the probability
distributions can be tweeked to affect the types of features
found in the rules like character classes, alternation, repetition, etc.

Install
-------

Will be automatically installed with the rest of Sniffles.


Options
-------

regexgen--Random Regular Expression Generator.

    usage: regexgen [-C char distribution] [-c number regex]
    [-D class distribution] [-f output re file]
    [-l lambda for length generation] [-n negation probability]
    [-o options chance] [-R repetition chance] [-r repetition distribution]
    [-t re structural type distribution] [-?] [-g]

-    -C Character Distribution: This sets the possibility of seeing
    particular characters or character types.  See a brief explanation of
    distibutions below for examples on how to use this.  By default
    this distribution is an equal distribution.  This distribution
    has five slots: ASCII Characters, Binary characters in \x00 format,
    Alphabetical letters (upper or lower case), Digits, and substitution
    classes (like \w).  An example input to this would be "10,20,10,40,20"
    which would mean 10% chance any generated char would come from 10% ASCII,
    20% binary, 10% letters, etc.  One Caveat is that ASCII chars that
    might cause problems with regular expression (like `[' or '{')
    are converted to hex representation (\x3b for example).
-    -c Number of regular expressions to generate.  Default is one.
-    -D Class Distribution: There are only two slots in the class
    distribution.  The first slot is the probability that the class is
    comprised of some number of randomly generated characters.  The
    second slot is the probability that the class is comprised of
    ranges (like a-z).
-    -f Output file name.  This sets the name of the file where the
    regular expressions are stored.  The default is a file named rand.re
    in the current working directory.
-    -g Groups: All regular expressions will have a common prefix with
    at least one or more other regular expressions (as long as there are
    more than one regex.)  A common prefix is just a regular expression
    that is the same for some set of regular expressions.  The total
    number of possible common prefixes is from 1 to 1/2 the size of the
    total regular expressions to generate.  The default value for this
    option is false.  This option takes no parameters.
-    -l Lambda for length:  This is the mean length for an exponentional
    distribution of regular expression lengths.  The default value is 10.
-    -n Negation probability: The probability that a character class will
    be a negation class ([^xyz]) rather than a normal character class ([xyz]).
    Default probability is 50%.
-    -o Option chance:  This is the chance for an option to be appended
    to the regular expression.  Current options are 'i', 'm', and 's'.
    A random number of options are added to the list with those options
    chose through a uniform distribution.
-    -R Repetition chance: The chance of repetition occuring after
    any structural component has been added to the regular expression.
-    -r Repetion distribution: The distribution of repetition structures.
    The slots are: Zero to one (?), Zero to many (*), one to many (+), and
    counting ({x,y}).
-    -t Re structural type distribution: The distribution for the
    primary structural components of the regular expression.  These
    are comprised of three slots, or categories: characters, classes,
    and alternation.  Note, alternation will simply generate a smaller
    regular expression up to the size of the remaining length left to
    the re.  In other words, alternation will result in several smaller
    regular expressions being joined into the overall regular expression.
    The alternation uses the exact same methodology in creating those
    smaller regular expressions.
-   -? Print this help.

    This generator will create random regular expressions.  It is possible
    to tune the structures within the regular expressions to a probability
    distribution, but currently not the content.  This is desirable in
    order to explore the maximum diversity in possible regular expressions
    (though not necessarily realistic regular expressions).
    The distributions are handled by creating a list of probabilities for
    the various possibilities, or slots, for a particular distribution.
    These are added as command line arguments using a simple string
    list like: "10,30,40,20".  The list should have as many values
    as it has slots.  The total of all values in the list should be
    100 and there should not be any fractions.  The value at each slot
    is the probability that that slot will be chosen.  For example,
    the base RE structural type distribution has three slots.  The
    first slot is the probability that the next structure type is
    a character (where a character can be a letter, digit, binary, ASCII,
    or substitution class (like \w)).  The second slot is for character
    classes like [ab@%], [^123], or [a-z].  The final slot is the probability
    of alternation occuring like (ab|cd).  With these three slots you can tune
    how often you would like the structures to appear in your regular
    expressions.  For example, regexgen -c 10 -t "80,10,10" would create
    10 regular expressions where 80% of the structures used would be
    characters, 10 percent would be character classes, and 10% alternation.

Random Rule Generator
=====================

The Random Rule Generator provides a mean for creating a number of randomly
generated rules with which to test a particular platform.  Currently,
rules generated meet either the Snort rule format or are just lines
of text.  In order for the Random Rule Generator to work you must have
a set of features defined.  Example features can be found in the
example_features folder and are further described below.

Install
-------

Automatically installed with Sniffles

Note: The Random Rule Generator makes use of the
Random Regex Generator for creating content of any kind.

Options
-------

Random Rule Generator

usage: rulegen -c [number of rules] -f [feature set]
        -o [outfile] [-s]

- -c  Number of rules: The number of rules to generate.
      Default is one.
- -f  Feature set: The file containing the feature set description.
      Please see the documentation for further explanation of
      feature sets and how to describe them.
- -o  Output file: output file to which rules are written.
      Default is rules.txt
- -s  Snort rule format: write rules to a snort rule format.
      No parameters, defaults to off.  When off, rules are just
      converted to a string format, whatever that may be based on
      the feature parser.

Feature Set
-----------

Features are used to describe potential aspects of rules used in
IDS.  For example, a packet filter might use rules that target
IP source and destination address.  In that case, it would be possible
to create a feature set describing how those IP source and destination
addresses should be generated.  More specifically, we make the
distinction between simple rules and complex rules.  The difference
between these two is the presence of ambiguous notations.  For
example, if we possessed an ambiguous notation of * to mean any
IP address, then we could say that * represents an ambigous notation.
Further, we know that a rule can also use a non-ambigous notation,
like 192.168.1.1.  That would represent a simple IP address as
it is a single fixed IP address without any possible ambiguous
notation.  We then further define the range of the particular
features (i.e. IP addresses across the entire 4 billion plus
possible IPv4 addresses, or just some subset of that).

The features ultimately define all of the aspects of for an
arbitrary rule.  Given a feature set and a valid rule format,
it becomes possible to randomly generate an arbitrary number
of rules that use those features. In this manner, it is possible 
to generate test rule sets that will examine the IDS across a
vector that is often missed.

Features are defined in a semi-colon separated list one feature per line
type=feature; list of arguments in key=value pairs, lists using python
formatting (i.e. [a, ..., z]).  Feature define specific portions of a
target rule format.  Features may be extended to add more functionality.
Optionally, one can extend the ability of the features by creating a new
rule format.

Current Feature Types:

1. Feature -- generic feature
2. Content -- Content Feature
3. IP -- IP Feature
4. Protocol -- Protocol Feature

Ambiguous lists should be written as lists like [x:y]
for a range, [x,y] for a list, {x1,x2,x3} for a set
or just * for a wildcard or similar single option.

Example about ambiguous list:
```
ambiguity_list=[[2:9]]
it will generate [3:4], [5:6], etc (any [x:y] such that
x <= y and x >= 2 and y > x and y <= 9).

ambiguity_list=[[3,20]]
it will generate [3,9,10], [3,4,8,12], etc (any list [x1,x2,x3,..]
such that all values falling between 3 and 20.

ambiguity_list=[{5,6,10}]
it will generate a subset of {5,6,10} such as {5,10}, {5}.

ambiguity_list=[[2:9],[3,20],{5,6,11}]
it will pick one of [2:9], [3,20], and {5,6,11} and
generate a corresponding instance (see above)
```

Example for feature file:
```
type=protocol; name=proto; proto_list=[TCP,UDP,ICMP]; complexity_prob=0;ambiguity_list=None;
type=ip; name=sip; version=4; complexity_prob=100;
```
the above defines two features, a protocol features and a source
IP feature.  The protocol is named proto, which is important
only for the rule formatter, and the valid protocols are:
IP, TCP, UDP, and ICMP.  The IP feature is defined as IPv4
and all rules will be complex.  IP complexity is already
part of the class and need not be added in the feature definition.
This will create IP addresses using CIDR notation.

Generic Feature Attributes:

- Feature_name: Informational attribute, potentially valuable for
                the rule formatter.
- lower_bound: The lower boundary of possible values.  Assumes
               the feature is a number.
- upper_bound: Opposite of lower_bound.
- complexity_prob: The probability of using complex features for a
                   rule.  From 0 to 100.  Defaults to 0.
                   When complex features are used, an ambigous notation
                   is randomly selected from the ambiguity list, or
                   if the feature defines a specific ambiguity (like
                   IP addresses) then that is used.  When complex
                   features are not used, a value is generated using
                   the boundaries, or, in the case of Content,
                   using a set of distribution values that will
                   restrict the generated string to a series
                   of ASCII characters.
- ambiguity_list: A list of possible ambiguous notations.
                  Comma-separated list using python formatting
                  (i.e. [a, b, c]).
- toString(): Prints out an instance of a rule given this particular
              feature set.

Content Feature -- Inherits from Feature:
- regex: True or False.  If True, will use pcre formatting for
         regex as well as possible add the options, i, s, or
         m to the regex.
- length: Defines the average length of the generated
          content.

Protocol Feature -- Inherits from Feature:
- proto_list: Defines the list of possible protocols,
                 as a comma-separated list (i.e [TCP,
                 UDP]).

IP Feature -- Inherits from Feature:
- version: 4 for IP version 4, 6 for IP version 6.
           Defaults to version 4.

Ambigous notation for ranges, lists, sets:

Range Notation:
  [x:y]  means from x to y (inclusive).

List notation:
  [x,y] means list of some randomly determined number of values
  where each value is greater than or equal to x
  and smaller than or equal to y.

Set notation:
  {x1,x2,x3,x4} means a set of value x1, x2, x3, x4.  It
  will generate a subset set of original set.

Please look at the example feature sets in the
example_features folder for further examples.
More details as well as the academic theory
behind this are scheduled to be added later.
