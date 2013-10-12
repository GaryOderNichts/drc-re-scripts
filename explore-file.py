'''
This script is to be used just after loading a lvc firmware into ida
It defines exception vectors nicely, creates segments, marks some
common functions, and analyzes the .text segment
'''

from idaapi import *
from idautils import *
from idc import *

def setup_compiler_options():
    cc = compiler_info_t()
    cc.cm = CM_N32_F48 | CM_CC_CDECL
    cc.defalign = 1
    cc.id = COMP_GNU
    cc.size_b = 4
    cc.size_e = 4
    cc.size_i = 4
    cc.size_l = 4
    cc.size_ll = 8
    cc.size_s = 2
    set_compiler(cc, 0)

def add_struct(name):
    sid = GetStrucIdByName(name)
    if sid != -1:
        DelStruc(sid)
	return AddStrucEx(-1, name, 0)

def add_base_types():
    if ParseTypes('typedef unsigned __int32 u32;', 0) > 0:
        print 'failed to types'
    
    id = add_struct('mmu_init_entry')
    mid = AddStrucMember(id, 'size', 0, 0x20000400,	-1, 4)
    mid = AddStrucMember(id, 'pa', 0x4, 0x20000400, -1, 4)
    mid = AddStrucMember(id, 'mva',	0x8, 0x20000400, -1, 4)
    mid = AddStrucMember(id, 'flags', 0xc, 0x20000400, -1, 4)
    
    id = add_struct('arm_scatter_entry')
    mid = AddStrucMember(id, 'arg0', 0, 0x20000400, -1, 4)
    mid = AddStrucMember(id, 'arg1', 0x4, 0x20000400, -1, 4)
    mid = AddStrucMember(id, 'arg2', 0x8, 0x20000400, -1, 4)
    mid = AddStrucMember(id, 'func', 0xc, 0x25500400, 0XFFFFFFFF, 4, 0XFFFFFFFF, 0, 0x000002)

def process_xcpt_vectors():
    do_unknown_range(0, 0x40, 0)

    xcpt_names = {
        0x00 : 'reset',
        0x04 : 'undef',
        0x08 : 'swi',
        0x0c : 'insn_abrt',
        0x10 : 'data_abrt',
        0x14 : 'reserved',
        0x18 : 'irq',
        0x1c : 'fiq'
    }
    reset_handler = BADADDR
    handler_eas = {}
    for ea in xrange(0, 0x20, 4):
        vect = DecodeInstruction(ea)
        handler = BADADDR
        if vect.itype == ARM_b:
            handler = vect.Op1.addr
        elif vect.itype == ARM_ldrpc:
            if vect.Op2.dtyp == dt_dword:
                handler = Dword(vect.Op2.addr)
        if handler != BADADDR:
            # account for thumbness
            handler &= ~1
            # always update the counts
            handler_eas[handler] = handler_eas[handler] + 1 if handler in handler_eas else 1
            if ea == 0: reset_handler = handler
            # already marked? -> skip
            if isFunc(getFlags(handler)):
                continue
            # mark it up
            MakeFunction(handler)
            set_name(handler, xcpt_names[ea] + '_handler')
    # find the common unhandled exception handler
    for ea, hitcount in handler_eas.items():
        if hitcount > 1 and not func_does_return(ea):
            set_name(ea, 'unhandled_exception_handler')
    
    # mark the vectors
    for i in xrange(0, 0x20, 4):
        MakeCode(i)
    Wait()
    
    # walk into exception handler and find mmu/bss settings
    setup_mmu_insn = FindText(reset_handler, SEARCH_DOWN, 0, 0, 'BL')
    setup_mmu = [x for x in XrefsFrom(setup_mmu_insn, 0) if x.type == 17][0].to
    # do mmu stuff
    set_name(setup_mmu, 'setup_mmu')
    mmu_settings_insn = FindText(setup_mmu, SEARCH_DOWN, 0, 0, 'ADR')
    mmu_init_entries = [x for x in XrefsFrom(mmu_settings_insn, 0) if x.type == 1][0].to
    ea = mmu_init_entries
    num_entries = 0
    while Dword(ea) != 0:
        num_entries += 1
        ea += GetStrucSize(GetStrucIdByName('mmu_init_entry'))
    MakeStruct(mmu_init_entries, 'mmu_init_entry')
    MakeArray(mmu_init_entries, num_entries)
    Wait()
    # do bss stuff
    last_insn = decode_prev_insn(get_func(reset_handler).endEA)
    scatter_init_insn = [x for x in XrefsFrom(last_insn, 0) if x.type == 19][0].to
    scatter_addr_insn = FindText(scatter_init_insn, SEARCH_DOWN, 0, 0, 'ADR')
    scatter_addrs = [x for x in XrefsFrom(scatter_addr_insn, 0) if x.type == 1][0].to
    if not isOff0(getFlags(scatter_addrs)) or not isOff0(getFlags(scatter_addrs + 4)):
        OpOff(scatter_addrs, 0, scatter_addrs)
        MakeArray(scatter_addrs, 2)
    Wait()
    sctr_beg, sctr_end = [x.to for x in XrefsFrom(scatter_addrs, 0) if x.type == 1 and x.to != scatter_addrs]
    num_sctr = (sctr_end - sctr_beg) / GetStrucSize(GetStrucIdByName('arm_scatter_entry'))
    MakeStruct(sctr_beg, 'arm_scatter_entry')
    MakeArray(sctr_beg, num_sctr)
    Wait()
    
    # get regions from the structs
    segms = []
    sizeof = GetStrucSize(GetStrucIdByName('mmu_init_entry'))
    for ea in xrange(mmu_init_entries, mmu_init_entries + num_entries * sizeof, sizeof):
        segms.append((Dword(ea+8), Dword(ea+0), Dword(ea+0xc)))
    print 'mmu regions:'
    for segm in segms:
        print '%8x %8x %4x' % (segm)
    bsss = []
    sizeof = GetStrucSize(GetStrucIdByName('arm_scatter_entry'))
    for ea in xrange(sctr_beg, sctr_beg + num_sctr * sizeof, sizeof):
        bsss.append((Dword(ea+4), Dword(ea+8)))
    print 'scatterload sections:'
    for bss in bsss:
        print '%8x %8x' % (bss)
    
    # process segments using above regions
    textSeg = getseg(0)
    set_segm_name(textSeg, '.text')
    dataSegBegin = FindBinary(textSeg.endEA, 0, '02 42 52 e8 04')
    if dataSegBegin != BADADDR:
        dataSegEnd = textSeg.endEA
        textSeg.endEA = dataSegBegin
        seg = segment_t()
        seg.startEA = dataSegBegin
        seg.endEA = dataSegEnd
        add_segm_ex(seg, '.idata', 'DATA', ADDSEG_SPARSE)
    
    bss_high = 0
    for i, bss in enumerate(bsss):
        seg = segment_t()
        seg.startEA = bss[0]
        seg.endEA = bss[0] + bss[1]
        add_segm_ex(seg, '.bss'+str(i), 'DATA', ADDSEG_SPARSE)
        bss_high = max(seg.endEA, bss_high)
    
    seg = segment_t()
    seg.startEA = bss_high
    seg.endEA = segms[0][0] + segms[0][1]
    add_segm_ex(seg, '.data', 'DATA', ADDSEG_SPARSE)
    
    for segm, name in zip(segms[1:], ['blah', 'tlb', 'mmio']):
        seg = segment_t()
        seg.startEA = segm[0]
        seg.endEA = segm[0] + segm[1]
        if segm[0] == 0xe0000000:
            seg.endEA = 0xf0010000 # not the actual space, but enough anyways
        add_segm_ex(seg, name, 'DATA', ADDSEG_SPARSE)

def patch_assert_hang():
    textSeg = get_segm_by_name('.text')
    ea = textSeg.startEA
    while ea < textSeg.endEA:
        b_self = FindBinary(ea, SEARCH_DOWN | SEARCH_CASE, 'e7fe')
        ea = b_self + 2
        # this method depends on ida having already marked it as a function
        if isFunc(getFlags(b_self)):
            print 'patch assert_hang @ %8x' % (b_self)
            patch_word(b_self, 0x4770)
            set_name(b_self, 'assert_hang')
            # Needed to prevent AnalyzeArea magically thinking it's noret again
            SetType(b_self, 'void assert_hang(void);')
            get_func(b_self).flags &= ~FUNC_NORET
            reanalyze_callers(b_self, False)
            break

def do_svc_a():
    textSeg = get_segm_by_name('.text')
    svc_a = FindBinary(textSeg.startEA, SEARCH_DOWN | SEARCH_CASE, 'ef00000a')
    svc_a_func = get_func(svc_a)
    if svc_a_func is None:
        # laziness
        print 'log_message doesn\'t appear to have been marked as a function...'
        return
    print 'svc_a @ %8x' % (svc_a_func.startEA)
    set_name(svc_a_func.startEA, 'svc_a')
    SetType(svc_a_func.startEA, 'void svc_a(void);')

def num_fcrefs(ea):
    num = 0
    fcref = get_first_fcref_to(ea)
    while fcref != BADADDR:
        num += 1
        fcref = get_next_fcref_to(ea, fcref)
    return num
    
def do_log():
    textSeg = get_segm_by_name('.text')
    ea = textSeg.startEA
    bx_lr_funcs = []
    while ea < textSeg.endEA:
        bx_lr = FindBinary(ea, SEARCH_DOWN | SEARCH_CASE, '4770')
        ea = bx_lr + 2
        if isFunc(getFlags(bx_lr)):
            bx_lr_funcs.append((bx_lr, num_fcrefs(bx_lr)))
    # second highest is log() (highest is svc_a)
    # gross but...most of this file is :D
    log_ea = sorted(bx_lr_funcs, key = lambda func: func[1])[-2][0]
    print 'log @ %8x' % (log_ea)
    set_name(log_ea, 'log')
    SetType(log_ea, 'void log(char *fmt, ...);')

def unmark_first_mismarked_code():
    textSeg = get_segm_by_name('.text')
    # try to find and remove the chunk of thumb which
    # ida incorrectly thinks is arm...
    ea = textSeg.startEA
    while ea < textSeg.endEA:
        thumb_push = FindBinary(ea, SEARCH_DOWN | SEARCH_CASE, '? b4')
        ea = thumb_push + 2
        if thumb_push & 1: continue
        if not get_func(thumb_push) is None: continue
        if isCode(getFlags(thumb_push)) and GetReg(thumb_push, 't') == 0:
            print 'undefining mismarked code @ %8x' % (thumb_push)
            mismarked_size = FindUnexplored(thumb_push, SEARCH_DOWN) - thumb_push
            do_unknown_range(thumb_push, mismarked_size, DOUNK_EXPAND)
            SetReg(thumb_push, 't', 1)
            Wait()
            break

def make_unreferenced_funcs():
    # After analysis, there can be many functions which ida identifies
    # correctly, however cannot see how control flow reaches them. This
    # results in code regions which are not marked as functions, which
    # screws up trying to use get_func() at later points.
    # Here, we effectively visit all these regions and press 'P' on them :)
    textSeg = get_segm_by_name('.text')
    ea = textSeg.startEA
    while ea < textSeg.endEA:
        ea = NextHead(ea, textSeg.endEA)
        if ea == BADADDR: break
        func = get_func(ea)
        if not func is None and func.endEA > ea:
            ea = func.endEA - 1
            continue
        if isCode(getFlags(ea)):
            print '%8x making func...' % (ea)
            MakeFunction(ea)
            Wait()
    
if __name__ == '__main__':
    setup_compiler_options()
    add_base_types()
    process_xcpt_vectors()
    patch_assert_hang()
    unmark_first_mismarked_code()
    
    textSeg = get_segm_by_name('.text')
    AnalyzeArea(textSeg.startEA, textSeg.endEA)
    
    make_unreferenced_funcs()
    do_svc_a()
    do_log()
    print 'Done, please run "Reanalyze program"!'
