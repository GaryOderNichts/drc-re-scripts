import sys, os, array, struct
from construct import *
import nalwriter

'''
Note this script uses incorrect nomenclature some places,
because many things were found by trial and error. Refer
to the wiki or sample C++ code for correct naming.
However it should function correctly.
'''

VSTRMHeader = BitStruct('VSTRMHeader',
    BitField('magic', 4),
    BitField('packet_type', 2),
    BitField('seqid', 10),
    BitField('init', 1),
    BitField('frame_begin', 1),
    BitField('chunk_end', 1),
    BitField('frame_end', 1),
    BitField('has_timestamp', 1),
    BitField('packet_size', 11),
    BitField('timestamp', 32)
)

CAMERA_DIMENSIONS  = (640, 480)
GAMEPAD_DIMENSIONS = (854, 480)

if len(sys.argv) != 3:
    print '[c|g] <file>'
    exit(1)
    
fi_name = sys.argv[2]
fo_name = fi_name + '.h264'
out_res = CAMERA_DIMENSIONS if sys.argv[1] == 'c' else GAMEPAD_DIMENSIONS

def write_frame(frame_num, is_I_frame, chunks):
    with open(fo_name, 'ab') as fo:
        fo.write('\0\0\0\1')
        header_val = 0
        if is_I_frame:
            header_val = 0x25b804ff
        else:
            header_val = 0x21e003ff | ((frame_num & 0xff) << 13)
        fo.write(struct.pack('>L', header_val))
        for chunk in chunks:
            escaped_chunk = array.array('B', chunk[:2])
            for i in xrange(2, len(chunk)):
                if chunk[i] <= 3 and escaped_chunk[-2] == 0 and escaped_chunk[-1] == 0:
                    escaped_chunk.extend([3])
                escaped_chunk.extend([chunk[i]])
            fo.write(escaped_chunk)

def verify_vstrm_header(hdr):
    return hdr.magic == 0xf and hdr.packet_type == 0 and hdr.has_timestamp == 1 and hdr.frame_begin & hdr.frame_end == 0
    
class extended_options:
    framerate_lut = {0:59.94,1:50,2:29.97,3:25}
    def __init__(s, data):
        s.idr, s.unk81 = False, False
        s.framerate = s.framerate_lut[0]
        s.flag_set, s.flag_clear = False, False
        s.unk_val = None
        off = 0
        while True:
            b = data[off]
            if b == 0x80:
                s.idr = True
            elif b == 0x81:
                s.unk81 = True
            elif b == 0x82:
                off += 1
                s.framerate = s.framerate_lut[data[off]]
            elif b == 0x83:
                s.flag_set = True
            elif b == 0x84:
                s.flag_clear = True
            elif b == 0x85:
                off += 1
                s.unk_val = data[off]
            off += 1
            if off == 8 or data[off] == 0:
                break
    def __repr__(s):
        msg = ['{:}Hz {:}'.format(s.framerate, 'IDR' if s.idr else 'non-IDR')]
        if s.unk_val != None:
            msg.append('{:02x}'.format(s.unk_val))
        if s.unk81:
            msg.append('81')
        if s.flag_set:
            msg.append('set flag')
        if s.flag_clear:
            msg.append('clear flag')
        return ', '.join(msg)
         
print_slice_data = False
exit_on_bad_frame = False
         
with open(fi_name, 'rb') as fi:
    fi.seek(0, 2)
    fsize = fi.tell()
    fi.seek(0)
    o = 0
    time_bias = lastframetime = 0
    seqid_last = None
    frame_is_bad = False
    seen_idr = False
    frame_num = 0
    frame_options = None
    slice_data = []
    frame_size = 0
    packet_infos = []
    packet_size = 0
    frame_num_slices = 0
    while o < fsize:
        hdr = VSTRMHeader.parse_stream(fi)
        if not verify_vstrm_header(hdr):
            print 'parse failed'
            print hdr
            #exit(1)
            
        options = array.array('B')
        options.fromfile(fi, 8)
        pkt = fi.read(hdr.packet_size)
        
        # drop dupes
        if hdr.seqid == seqid_last:
            continue
        if seqid_last != None and hdr.seqid != (seqid_last + 1) & 0x3ff:
            print 'missing packets before {:4x} frame {:4x}'.format(hdr.seqid, frame_num)
            frame_is_bad = True
        #print hdr
        
        if hdr.frame_begin:
            packet_infos = []
            frame_size = 0
            frame_is_bad = False
            frame_num_slices = 0
            frame_options = extended_options(options)
            if frame_options.idr:
                frame_num = 0
                time_bias = lastframetime = hdr.timestamp
                openmode = 'ab' if seen_idr else 'wb'
                with open(fo_name, openmode) as fo:
                    fo.write(nalwriter.get_sps(out_res))
                    fo.write(nalwriter.get_pps())
                seen_idr = True
            frame_timestamp = (hdr.timestamp - time_bias) / 1000.0
            slice_data = [array.array('B')]
            timediff = hdr.timestamp - lastframetime
            period = (1.0 / frame_options.framerate) * 1000000.0
            slack = period * .01
            if timediff != 0 and (timediff < period - slack or timediff > period + slack):
                print 'timediff off by {:}ms'.format((period - timediff) / 1000.0)
        
        if len(slice_data) - 1 != frame_num_slices:
            # needed if frame_begin packet is missing
            slice_data.append(array.array('B'))
        slice_data[frame_num_slices].extend(array.array('B', pkt))
        
        packet_size += hdr.packet_size
        
        if hdr.chunk_end:
            frame_num_slices += 1
            if not hdr.frame_end:
                slice_data.append(array.array('B'))
            packet_infos.append('{:4x}'.format(packet_size))
            frame_size += packet_size
            packet_size = 0
            
        if hdr.frame_end and frame_options == None:
            packet_infos = []
            frame_num_slices = 0
            slice_data = [array.array('B')]
            frame_num += 1
            continue
        
        if hdr.frame_end:
            if not frame_num_slices * frame_options.unk_val == 30:
                print 'irregular number of slices'
                frame_is_bad = True
            lastframetime = hdr.timestamp
            print '{:-4x} {:10.10}ms size {:4x} | {:} | {:}'.format(
                frame_num, frame_timestamp, frame_size,
                frame_options,
                ' '.join(packet_infos))
            if frame_is_bad and seen_idr and exit_on_bad_frame:
                print 'bad frame, exiting early'
                exit(1)
            if not frame_is_bad and seen_idr:
                write_frame(frame_num, frame_options.idr, slice_data)
            if print_slice_data:
                for slice in slice_data:
                    print slice.tostring().encode('hex')
            # need to reset here as well, in case frame_begin is missing
            packet_infos = []
            frame_num_slices = 0
            slice_data = [array.array('B')]
            frame_num += 1
        
        seqid_last = hdr.seqid
        o = fi.tell()