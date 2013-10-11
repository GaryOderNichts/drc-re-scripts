'''
This script autonames functions containing drefs to strings ending in ".c"
'''

from idaapi import *
from idautils import *
from idc import *

import os

def MakeNameAuto(ea, name):
    i = 0
    fname = name
    while not set_name(ea, fname, SN_NON_AUTO | SN_NOCHECK | SN_NOWARN):
        fname = name + '_%x' % (i)
        i += 1

if __name__ == '__main__':
    dref_map = {}
    for s in (s for s in Strings() if str(s).find('.c') > 0):
        func_name = os.path.basename(str(s))[:-2]
        dref = 0
        while True:
            dref = get_next_dref_to(s.ea, dref)
            if dref == BADADDR: break
            dref_func = get_func(dref)
            if dref_func is None: continue
            if dref_func in dref_map and dref_map[dref_func] != func_name:
                print 'function references two source files! (using first)'
                continue
            dref_map[dref_func.startEA] = func_name
            
    for func_ea, name in dref_map.items():
        MakeNameAuto(func_ea, name)
