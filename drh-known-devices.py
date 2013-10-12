from construct import *
import sys, os

DRHDeviceEntry = Struct('DRHDeviceEntry',
    UBInt8('unk'),
    UBInt8('enable_radio'),
    UBInt8('tx_power_level'),
    UBInt8('rx_threshold'),
    UBInt8('rate_adaptation'),
    UBInt8('packet_retry'),
    UBInt8('packet_aggregation'),
    String('country_code', length = 3),
    UBInt8('country_code_length'),
    UBInt8('country_code_revision'),
    UBInt8('channel_assignment'),
    UBInt8('antenna_select'),
    UBInt8('authentication_method'),
    UBInt8('encryption_method'),
    String('network_name', length = 0x20),
    UBInt8('network_name_length'),
    String('network_key', length = 0x40),
    UBInt8('network_key_length'),
    Padding(0x8e)
)

DRHDeviceList = Struct('DRHDeviceList',
    RepeatUntil(lambda obj, ctx: obj.network_name_length == 0xff, DRHDeviceEntry)
)

def fixup_list(entries):
    entries = entries[:len(entries)-1]
    for x in entries:
        x.country_code = x.country_code[:x.country_code_length]
        x.network_name = x.network_name[:x.network_name_length]
        x.network_key  = x.network_key [:x.network_key_length]
    return entries

def parse_device_list(drh_dump):
    drh_dump.seek(0x10000)
    devices_list = fixup_list(DRHDeviceList.parse_stream(drh_dump).DRHDeviceEntry)
    identity_entry = devices_list[0]
    print 'identity:', identity_entry
    for i, d in enumerate(devices_list[1:]):
        print 'device {:4x} {:}'.format(i, d)
        
if __name__ == '__main__':
    if len(sys.argv) == 2 and os.path.exists(sys.argv[1]):
        with open(sys.argv[1], 'rb') as drh:
            parse_device_list(drh)