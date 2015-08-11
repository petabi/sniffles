import struct
import random
import sys


class TrafficWriter:
    """
        The TrafficWriter class can be used to write out a
        series of packets into the traditional pcap format.
        To use this class, call the constructor and provide
        the name of the save file.  When you have a packet to
        write, call write_packet(length, pkt) where length
        is the length of the packet and pkt is the binary
        string for the packet.  When finished, call close_save_file()
        to close the file handle.

        Optional api:
            set_timestamp: Timestamps default to 0 secs and 0 msecs.
            if you want a different time, call set_timestamp and
            provide the start time of the capture you wish (secs, msecs).
            All packets will move forward from this timestamp after it is
            set, so it should be set prior to the start of writing packets.

            increment_timestamp:  Timestamps are incremented by 1 msec
            after each packet is written.  If you wish to increment by more,
            you may call this function between packet writes and provide the
            amount of time (secs, msecs) to increment the timestamp.

            open_save_file():  allows you to open a save file outside of
            the constructor.  That way you can build the object then
            set_file_name(name) and then open_save_file().
    """
    writer_handle = None
    current_time_sec = 0
    current_time_usec = 0

    def __init__(self, save_file=None, start_ts=0):
        if save_file:
            self.save_file = save_file
            self.open_save_file()
        self.set_timestamp(start_ts, 0)

    def close_save_file(self):
        if self.writer_handle:
            self.writer_handle.close()

    def increment_timestamp(self, secs=0, msecs=0):
        self.current_time_sec += secs
        self.current_time_usec += msecs
        if self.current_time_usec > 1000000:
            self.current_time_sec += 1
            self.current_time_usec -= 1000000

    def get_timestamp(self):
        return (self.current_time_sec + (self.current_time_usec/1000000))

    def open_save_file(self):
        if self.save_file:
            try:
                self.writer_handle = open(self.save_file, 'wb')
            except:
                print("Could not open save file for writing: ", self.save_file)
                sys.exit(1)
            self.write_pcap_file_header()
        else:
            print("No name for the pcap save file.")

    def set_file_name(self, save_file=None):
        if save_file:
            self.save_file = save_file
        else:
            print("Did not set a name for the save file.")

    def set_timestamp(self, secs=0, usecs=0):
        self.current_time_sec = secs
        self.current_time_usec = usecs
        while self.current_time_usec >= 1000000:
            self.current_time_sec += 1
            self.current_time_usec -= 1000000

    def write_packet(self, len=0, pkt=None, secs=-1, usecs=-1):
        if pkt and self.writer_handle:
            time_lapse = 0
            if secs < 0:
              secs = self.current_time_sec
            if usecs < 0:
              usecs = self.current_time_usecs
            self.set_timestamp(secs, usecs)
            pcap_hdr = struct.pack("IIII", self.current_time_sec,
                                   self.current_time_usec, len, len)
            self.writer_handle.write(pcap_hdr)
            self.writer_handle.write(pkt)
        else:
            print("No packet to write!")
        return self.current_time_sec, self.current_time_usec

    def write_pcap_file_header(self):
        if not self.writer_handle:
            return

        magic_number = 0xa1b2c3d4
        version_major = 2
        version_minor = 4
        thiszone = 0
        sigfigs = 0
        snaplen = 0xffff
        network = 1
        global_header = struct.pack('IHHIIII', magic_number,
                                    version_major, version_minor,
                                    thiszone, sigfigs, snaplen,
                                    network)
        self.writer_handle.write(global_header)
