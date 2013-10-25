import sys, array
import construct
from scapy.all import *

MSGHeader = construct.Struct('MSGHeader',
    construct.ULInt16('message_id'),
    construct.ULInt16('payload_size'),
    construct.Array(lambda ctx: ctx.payload_size, construct.UBInt8("payload"))
)

VSTRMHeader = construct.BitStruct('VSTRMHeader',
    construct.Nibble('magic'),
    construct.BitField('packet_type', 2),
    construct.BitField('seq_id', 10),
    construct.Flag('init'),
    construct.Flag('frame_begin'),
    construct.Flag('chunk_end'),
    construct.Flag('frame_end'),
    construct.Flag('has_timestamp'),
    construct.BitField('payload_size', 11),
    construct.BitField('timestamp', 32)
)

class VSTRMExtendedHeader:
    framerate_lut = { 0 : 59.94, 1 : 50, 2 : 29.97, 3 : 25 }
    
    def __init__(s, data):
        s.is_idr, s.unk81 = False, False
        s.framerate = s.framerate_lut[0]
        s.force_decode, s.unforce_decode = False, False
        s.mb_rows_in_chunk = 0
        off = 0
        while True:
            b = data[off]
            if b == 0x80:
                s.is_idr = True
            elif b == 0x81:
                s.unk81 = True
            elif b == 0x82:
                off += 1
                s.framerate = s.framerate_lut[data[off]]
            elif b == 0x83:
                s.force_decode = True
            elif b == 0x84:
                s.unforce_decode = True
            elif b == 0x85:
                off += 1
                s.mb_rows_in_chunk = data[off]
            off += 1
            if off >= 8 or data[off] == 0:
                break

ASTRMBaseHeader = construct.BitStruct('ASTRMBaseHeader',
    construct.BitField('format', 3),
    construct.Bit('channel'),
    construct.Flag('vibrate'),
    construct.Bit('packet_type'),
    construct.BitField('seq_id', 10),
    construct.BitField('payload_size', 16)
)
ASTRMAudioHeader = construct.Struct('ASTRMAudioHeader',
    construct.ULInt32('timestamp'),
    construct.Array(lambda ctx: ctx.payload_size, construct.UBInt8("data"))
)
ASTRMMsgHeader = construct.Struct('ASTRMMsgHeader',
    # This is kind of a hack, (there are two timestamp fields, which one is used depends on packet_type
    construct.ULInt32('timestamp_audio'),
    construct.ULInt32('timestamp'),
    construct.Array(2, construct.ULInt32('freq_0')), # -> mc_video
    construct.Array(2, construct.ULInt32('freq_1')), # -> mc_sync
    construct.ULInt8('vid_format'),
    construct.Padding(3)
)
ASTRMHeader = construct.Struct('ASTRMHeader',
    construct.Embed(ASTRMBaseHeader),
    construct.Switch("format_hdr", lambda ctx: ctx.packet_type,
        {
            0 : construct.Embed(ASTRMAudioHeader),
            1 : construct.Embed(ASTRMMsgHeader),
        },
        default = construct.Pass
    )
)

CMD0Header = construct.Struct('CMD0Header',
    construct.UBInt8('magic'),
    construct.UBInt8('unk_0'),
    construct.UBInt8('unk_1'),
    construct.UBInt8('unk_2'),
    construct.UBInt8('unk_3'),
    construct.UBInt8('flags'),
    construct.UBInt8('id_primary'),
    construct.UBInt8('id_secondary'),
    construct.UBInt16('error_code'),
    construct.UBInt16('payload_size_cmd0')
)
'''
CMD1Header = construct.Struct('CMD1Header',
    
)
'''
CMD2Header = construct.Struct('CMD2Header',
    construct.ULInt16('JDN_base'),
    construct.Padding(2),
    construct.ULInt32('seconds')
)
CMDHeader = construct.Struct('CMDHeader',
    construct.ULInt16('packet_type'),
    construct.ULInt16('cmd_id'),
    construct.ULInt16('payload_size'),
    construct.ULInt16('seq_id'),
    construct.Switch('cmd_hdr', lambda ctx: ctx.cmd_id,
        {
            0 : construct.If(lambda ctx: ctx.payload_size >= CMD0Header.sizeof(), construct.Embed(CMD0Header)),
            2 : construct.If(lambda ctx: ctx.payload_size == CMD2Header.sizeof(), construct.Embed(CMD2Header)),
        },
        default = construct.Pass
    )
)

if len(sys.argv) != 2:
    print 'pcap'
    exit(1)
    
pcap = rdpcap(sys.argv[1])

PORT_BOOTPS = 67
PORT_BOOTPC = 68

PORT_MSG_H   = 50010
PORT_MSG_C   = 50110
PORT_VSTRM_H = 50020
PORT_VSTRM_C = 50120
PORT_ASTRM_H = 50021
PORT_ASTRM_C = 50121
PORT_INPUT_H = 50022
PORT_INPUT_C = 50122
PORT_CMD_H   = 50023
PORT_CMD_C   = 50123

def direction_str(packet):
    return 'C->H' if packet[IP].dst == '192.168.1.10' else 'H->C'

def handle_dhcp(packet):
    if display_non_stream:
        print packet.display()

def handle_input(packet):
    #print '.'
    pass

class timediffer:
    def __init__(s):
        s.pkt_prev, s.pkt_tot = 0, 0
        s.ts_prev, s.ts_tot = 0, 0
    def inc(s, pkt_time, ts_time):
        if s.pkt_prev == 0: s.pkt_prev = pkt_time
        if s.ts_prev == 0: s.ts_prev = ts_time
        pkt_diff = pkt_time - s.pkt_prev
        ts_diff = ts_time - s.ts_prev
        s.pkt_tot += pkt_diff
        s.ts_tot += ts_diff
        s.pkt_prev = pkt_time
        s.ts_prev = ts_time
        return ((pkt_diff, s.pkt_tot), (ts_diff, s.ts_tot))

a_times = timediffer()
v_times = timediffer()
def handle_vstrm(packet):
    #return
    global v_times
    d = VSTRMHeader.parse(packet[Raw].load)
    ext_offset = 4 if not d.has_timestamp else 8
    ext_header = VSTRMExtendedHeader(array.array('B', packet[Raw].load[ext_offset:ext_offset+8]))
    print 'VSTRM   {:15} id:{:5} init:{:1} beg:{:1} end:{:1} cend:{:1} IDR:{:1}'.format(d.timestamp, d.seq_id, d.init, d.frame_begin, d.frame_end, d.chunk_end, ext_header.is_idr)
    if d.frame_end:
        pkt, ts = v_times.inc(packet.time, d.timestamp)
        pkt_time_diff_i = pkt[0] * 1000000
        pkt_time_tot_i = pkt[1] * 1000000
        print '%i %i %i %i %i %i' % (
            pkt_time_diff_i, ts[0], pkt_time_diff_i - ts[0],
            pkt_time_tot_i, ts[1], pkt_time_tot_i - ts[1])

def handle_astrm(packet):
    #return
    global a_times
    d = ASTRMHeader.parse(packet[Raw].load)
    if d.packet_type == 0:
	print
	return
    print 'ASTRM:{:} {:15} id:{:5} {:}'.format(
        'D' if d.packet_type == 0 else 'S', d.timestamp, d.seq_id,
        '*vibrate*' if d.vibrate else '')
    if d.packet_type == 0:
        pkt, ts = a_times.inc(packet.time, d.timestamp)
        pkt_time_diff_i = pkt[0] * 1000000
        pkt_time_tot_i = pkt[1] * 1000000
        print '%i %i %i %i %i %i' % (
            pkt_time_diff_i, ts[0], pkt_time_diff_i - ts[0],
            pkt_time_tot_i, ts[1], pkt_time_tot_i - ts[1])
    if d.packet_type == 1:
        if not (d.freq_0[0] == d.freq_0[1] == d.freq_1[0] == d.freq_1[1] == 16000 and d.vid_format == 0):
            print 'wierd vid_format!', d

def handle_cmd(packet):
    return
    rawdata = packet[Raw].load
    d = CMDHeader.parse(rawdata)
    payload = 'cmd:{:x} {:}\n'.format(d.cmd_id, rawdata.encode('hex'))
    if d.cmd_id == 0 and d.payload_size > 0 and d.payload_size_cmd0 > 0:
        off = 8+CMD0Header.sizeof()
        payload += 'id:{:2x} subid:{:2x} {:}'.format(d.id_primary, d.id_secondary, rawdata[off:off+d.payload_size_cmd0].encode('hex'))
    elif d.cmd_id == 2 and d.payload_size > 0:
        JDN = d.JDN_base + d.seconds / 86400
        seconds_today = d.seconds % 86400
        payload += '{:} {:}'.format(JDN, seconds_today, d.JDN_base)
    print 'CMD: {:}'.format(payload)

def handle_msg(packet):
    return
    d = MSGHeader.parse(packet[Raw].load)
    print 'MSG: {:} {:}'.format(d.message_id, d.payload_size)

port_handlers = {
    PORT_BOOTPS : handle_dhcp,
    PORT_BOOTPC : handle_dhcp,
    PORT_INPUT_H : handle_input,
    PORT_VSTRM_H : handle_vstrm,
    PORT_VSTRM_C : handle_vstrm,
    PORT_ASTRM_H : handle_astrm,
    PORT_ASTRM_C : handle_astrm,
    PORT_CMD_H : handle_cmd,
    PORT_CMD_C : handle_cmd,
    PORT_MSG_H : handle_msg,
    PORT_MSG_C : handle_msg,
}

display_non_stream = False

for packet in pcap:
    try:
        dport = packet[UDP].dport
        if dport in port_handlers:
            if dport in (
                PORT_VSTRM_H, PORT_VSTRM_C,
                PORT_ASTRM_H, PORT_ASTRM_C,
                #PORT_CMD_H, PORT_CMD_C,
                #PORT_MSG_H, PORT_MSG_C
                ):
                print '{:<16} {:<5}'.format(packet.time, direction_str(packet)), 
            port_handlers[dport](packet)
        else:
            #print 'unhandled udp dport {:}'.format(dport)
            pass
    except IndexError:
        # packet doesn't have UDP layer
        if display_non_stream:
            print packet.display()
