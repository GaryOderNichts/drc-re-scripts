// Finds and names uitron api calls
//@author GaryOderNichts, memahaxx
//@category drc-re
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

import java.nio.ByteBuffer;

// TODO set full signatures
// https://ghidra.re/ghidra_docs/api/ghidra/app/util/parser/FunctionSignatureParser.html

public class find_uitron_apis extends GhidraScript {

    public static int swap32(int value) {
        int b1 = (value >>  0) & 0xff;
        int b2 = (value >>  8) & 0xff;
        int b3 = (value >> 16) & 0xff;
        int b4 = (value >> 24) & 0xff;

        return b1 << 24 | b2 << 16 | b3 << 8 | b4 << 0;
    }

    class APICall {
        public APICall(int _id, String _tfn, String _proto) {
            id = _id;
            tfn = _tfn;
            proto = _proto;
        }

        public int id; 
        public String tfn;  
        public String proto; 
    };

    APICall[] apis = {
        new APICall(-0x05, "TFN_CRE_TSK", "ER cre_tsk(ID tskid, T_CTSK *pk_ctsk);"),
        new APICall(-0x06, "TFN_DEL_TSK", "ER del_tsk(ID tskid);"),
        new APICall(-0x07, "TFN_ACT_TSK", "ER act_tsk(ID tskid);"),
        new APICall(-0x08, "TFN_CAN_ACT", "ER_UINT can_act(ID tskid);"),
        new APICall(-0x09, "TFN_STA_TSK", "ER sta_tsk(ID tskid, VP_INT stacd);"),
        new APICall(-0x0a, "TFN_EXT_TSK", "void ext_tsk();"),
        new APICall(-0x0b, "TFN_EXD_TSK", "void exd_tsk();"),
        new APICall(-0x0c, "TFN_TER_TSK", "ER ter_tsk(ID tskid);"),
        new APICall(-0x0d, "TFN_CHG_PRI", "ER chg_pri(ID tskid, PRI tskpri);"),
        new APICall(-0x0e, "TFN_GET_PRI", "ER get_pri(ID tskid, PRI *p_tskpri);"),
        new APICall(-0x0f, "TFN_REF_TSK", "ER ref_tsk(ID tskid, T_RTSK *pk_rtsk);"),
        new APICall(-0x10, "TFN_REF_TST", "ER ref_tst(ID tskid, T_RTST *pk_rtst);"),
        new APICall(-0x11, "TFN_SLP_TSK", "ER slp_tsk();"),
        new APICall(-0x12, "TFN_TSLP_TSK", "ER tslp_tsk(TMO tmout);"),
        new APICall(-0x13, "TFN_WUP_TSK", "ER wup_tsk(ID tskid);"),
        new APICall(-0x14, "TFN_CAN_WUP", "ER_UINT can_wup(ID tskid);"),
        new APICall(-0x15, "TFN_REL_WAI", "ER rel_wai(ID tskid);"),
        new APICall(-0x16, "TFN_SUS_TSK", "ER sus_tsk(ID tskid);"),
        new APICall(-0x17, "TFN_RSM_TSK", "ER rsm_tsk(ID tskid);"),
        new APICall(-0x18, "TFN_FRSM_TSK", "ER frsm_tsk(ID tskid);"),
        new APICall(-0x19, "TFN_DLY_TSK", "ER dly_tsk(RELTIM dlytim);"),
        new APICall(-0x1b, "TFN_DEF_TEX", "ER def_tex(ID tskid, T_DTEX *pk_dtex);"),
        new APICall(-0x1c, "TFN_RAS_TEX", "ER ras_tex(ID tskid, TEXPTN rasptn);"),
        new APICall(-0x1d, "TFN_DIS_TEX", "ER dis_tex();"),
        new APICall(-0x1e, "TFN_ENA_TEX", "ER ena_tex();"),
        new APICall(-0x1f, "TFN_SNS_TEX", "BOOL sns_tex();"),
        new APICall(-0x20, "TFN_REF_TEX", "ER ref_tex(ID tskid, T_RTEX *pk_rtex);"),
        new APICall(-0x21, "TFN_CRE_SEM", "ER cre_sem(ID semid, T_CSEM *pk_csem);"),
        new APICall(-0x22, "TFN_DEL_SEM", "ER del_sem(ID semid);"),
        new APICall(-0x23, "TFN_SIG_SEM", "ER sig_sem(ID semid);"),
        new APICall(-0x25, "TFN_WAI_SEM", "ER wai_sem(ID semid);"),
        new APICall(-0x26, "TFN_POL_SEM", "ER pol_sem(ID semid);"),
        new APICall(-0x27, "TFN_TWAI_SEM", "ER twai_sem(ID semid, TMO tmout);"),
        new APICall(-0x28, "TFN_REF_SEM", "ER ref_sem(ID semid, T_RSEM *pk_rsem);"),
        new APICall(-0x29, "TFN_CRE_FLG", "ER cre_flg(ID flgid, T_CFLG *pk_cflg);"),
        new APICall(-0x2a, "TFN_DEL_FLG", "ER del_flg(ID flgid);"),
        new APICall(-0x2b, "TFN_SET_FLG", "ER set_flg(ID flgid, FLGPTN setptn);"),
        new APICall(-0x2c, "TFN_CLR_FLG", "ER clr_flg(ID flgid, FLGPTN clrptn);"),
        new APICall(-0x2d, "TFN_WAI_FLG", "ER wai_flg(ID flgid, FLGPTN waiptn, MODE wfmode, FLGPTN *p_flgptn);"),
        new APICall(-0x2e, "TFN_POL_FLG", "ER pol_flg(ID flgid, FLGPTN waiptn, MODE wfmode, FLGPTN *p_flgptn);"),
        new APICall(-0x2f, "TFN_TWAI_FLG", "ER twai_flg(ID flgid, FLGPTN waiptn, MODE wfmode, FLGPTN *p_flgptn, TMO tmout);"),
        new APICall(-0x30, "TFN_REF_FLG", "ER ref_flg(ID flgid, T_RFLG *pk_rflg);"),
        new APICall(-0x31, "TFN_CRE_DTQ", "ER cre_dtq(ID dtqid, T_CDTQ *pk_cdtq);"),
        new APICall(-0x32, "TFN_DEL_DTQ", "ER del_dtq(ID dtqid);"),
        new APICall(-0x35, "TFN_SND_DTQ", "ER snd_dtq(ID dtqid, VP_INT data);"),
        new APICall(-0x36, "TFN_PSND_DTQ", "ER psnd_dtq(ID dtqid, VP_INT data);"),
        new APICall(-0x37, "TFN_TSND_DTQ", "ER tsnd_dtq(ID dtqid, VP_INT data, TMO tmout);"),
        new APICall(-0x38, "TFN_FSND_DTQ", "ER fsnd_dtq(ID dtqid, VP_INT data);"),
        new APICall(-0x39, "TFN_RCV_DTQ", "ER rcv_dtq(ID dtqid, VP_INT *p_data);"),
        new APICall(-0x3a, "TFN_PRCV_DTQ", "ER prcv_dtq(ID dtqid, VP_INT*p_data);"),
        new APICall(-0x3b, "TFN_TRCV_DTQ", "ER trcv_dtq(ID dtqid, VP_INT *p_data, TMO tmout);"),
        new APICall(-0x3c, "TFN_REF_DTQ", "ER ref_dtq(ID dtqid, T_RDTQ *pk_rdtq);"),
        new APICall(-0x3d, "TFN_CRE_MBX", "ER cre_mbx(ID mbxid, T_CMBX* pk_cmbx);"),
        new APICall(-0x3e, "TFN_DEL_MBX", "ER del_mbx(ID mbxid);"),
        new APICall(-0x3f, "TFN_SND_MBX", "ER snd_mbx(ID mbxid, T_MSG *pk_msg);"),
        new APICall(-0x41, "TFN_RCV_MBX", "ER rcv_mbx(ID mbxid, T_MSG **ppk_msg);"),
        new APICall(-0x42, "TFN_PRCV_MBX", "ER prcv_mbx(ID mbxid, T_MSG **ppk_msg);"),
        new APICall(-0x43, "TFN_TRCV_MBX", "ER trcv_mbx(ID mbxid, T_MSG **ppk_msg, TMO tmout);"),
        new APICall(-0x44, "TFN_REF_MBX", "ER ref_mbx(ID mbxid, T_RMBX *pk_rmbx);"),
        new APICall(-0x45, "TFN_CRE_MPF", "ER cre_mpf(ID mpfid, T_CMPF *pk_cmpf);"),
        new APICall(-0x46, "TFN_DEL_MPF", "ER del_mpf(ID mpfid);"),
        new APICall(-0x47, "TFN_REL_MPF", "ER rel_mpf(ID mpfid, VP blk);"),
        new APICall(-0x49, "TFN_GET_MPF", "ER get_mpf ( ID mpfid, VP *p_blk ) ;"),
        new APICall(-0x4a, "TFN_PGET_MPF", "ER pget_mpf ( ID mpfid, VP *p_blk ) ;"),
        new APICall(-0x4b, "TFN_TGET_MPF", "ER tget_mpf ( ID mpfid, VP *p_blk, TMO tmout ) ;"),
        new APICall(-0x4c, "TFN_REF_MPF", "ER ref_mpf(ID mpfid, T_RMPF *pk_rmpf);"),
        new APICall(-0x4d, "TFN_SET_TIM", "ER set_tim(SYSTIM *p_systim);"),
        new APICall(-0x4e, "TFN_GET_TIM", "ER get_tim(SYSTIM *p_systim);"),
        new APICall(-0x4f, "TFN_CRE_CYC", "ER cre_cyc ( ID cycid, T_CCYC *pk_ccyc ) ;"),
        new APICall(-0x50, "TFN_DEL_CYC", "ER del_cyc ( ID cycid ) ;"),
        new APICall(-0x51, "TFN_STA_CYC", "ER sta_cyc ( ID cycid ) ;"),
        new APICall(-0x52, "TFN_STP_CYC", "ER stp_cyc ( ID cycid ) ;"),
        new APICall(-0x53, "TFN_REF_CYC", "ER ref_cyc ( ID cycid, T_RCYC *pk_rcyc ) ;"),
        new APICall(-0x55, "TFN_ROT_RDQ", "ER rot_rdq(PRI tskpri);"),
        new APICall(-0x56, "TFN_GET_TID", "ER get_tid(ID *p_tskid);"),
        new APICall(-0x59, "TFN_LOC_CPU", "ER loc_cpu();"),
        new APICall(-0x5a, "TFN_UNL_CPU", "ER unl_cpu();"),
        new APICall(-0x5b, "TFN_DIS_DSP", "ER dis_dsp();"),
        new APICall(-0x5c, "TFN_ENA_DSP", "ER ena_dsp();"),
        new APICall(-0x5d, "TFN_SNS_CTX", "BOOL sns_ctx () ;"),
        new APICall(-0x5e, "TFN_SNS_LOC", "BOOL sns_loc () ;"),
        new APICall(-0x5f, "TFN_SNS_DSP", "BOOL sns_dsp () ;"),
        new APICall(-0x60, "TFN_SNS_DPN", "BOOL sns_dpn () ;"),
        new APICall(-0x61, "TFN_REF_SYS", "ER ref_sys(T_RSYS *pk_rsys);"),
        new APICall(-0x65, "TFN_DEF_INH", "ER def_inh ( INHNO inhno, T_DINH *pk_dinh ) ;"),
        new APICall(-0x66, "TFN_CRE_ISR", "ER cre_isr ( ID isrid, T_CISR *pk_cisr ) ;"),
        new APICall(-0x67, "TFN_DEL_ISR", "ER del_isr ( ID isrid ) ;"),
        new APICall(-0x68, "TFN_REF_ISR", "ER ref_isr ( ID isrid, T_RISR *pk_risr ) ;"),
        new APICall(-0x69, "TFN_DIS_INT", "ER dis_int(INTNO eintno);"),
        new APICall(-0x6a, "TFN_ENA_INT", "ER ena_int(INTNO eintno);"),
        new APICall(-0x6b, "TFN_CHG_IXX", "ER chg_ixx( IXXXX ixxxx) ;"),
        new APICall(-0x6c, "TFN_GET_IXX", "ER get_ixx ( IXXXX *p_ixxxx) ;"),
        new APICall(-0x6d, "TFN_DEF_SVC", "ER def_svc ( FN fncd, T_DSVC *pk_dsvc ) ;"),
        new APICall(-0x6e, "TFN_DEF_EXC", "ER def_exc ( EXCNO excno, T_DEXC *pk_dexc ) ;"),
        new APICall(-0x6f, "TFN_REF_CFG", "ER ref_cfg ( T_RCFG *pk_rcfg ) ;"),
        new APICall(-0x70, "TFN_REF_VER", "ER ref_ver ( T_RVER *pk_rver ) ;"),
        new APICall(-0x71, "TFN_IACT_TSK", "ER iact_tsk(ID tskid);"),
        new APICall(-0x72, "TFN_IWUP_TSK", "ER iwup_tsk ( ID tskid ) ;"),
        new APICall(-0x73, "TFN_IREL_WAI", "ER irel_wai ( ID tskid ) ;"),
        new APICall(-0x74, "TFN_IRAS_TEX", "ER ras_tex(ID tskid, TEXPTN rasptn);"),
        new APICall(-0x75, "TFN_ISIG_SEM", "ER isig_sem( ID semid ) ;"),
        new APICall(-0x76, "TFN_ISET_FLG", "ER iset_flg ( ID flgid, FLGPTN setptn ) ;"),
        new APICall(-0x77, "TFN_IPSND_DTQ", "ER ipsnd_dtq ( ID dtqid, VP_INTdata ) ;"),
        new APICall(-0x78, "TFN_IFSND_DTQ", "ER ifsnd_dtq ( ID dtqid, VP_INTdata ) ;"),
        new APICall(-0x79, "TFN_IROT_RDQ", "ER irot_rdq ( PRI tskpri ) ;"),
        new APICall(-0x7a, "TFN_IGET_TID", "ER iget_tid ( ID *p_tskid ) ;"),
        new APICall(-0x7b, "TFN_ILOC_CPU", "ER iloc_cpu () ;"),
        new APICall(-0x7c, "TFN_IUNL_CPU", "ER iunl_cpu () ;"),
        new APICall(-0x7d, "TFN_ISIG_TIM", "ER isig_tim () ;"),
        new APICall(-0x81, "TFN_CRE_MTX", "ER cre_mtx ( ID mtxid, T_CMTX*pk_cmtx ) ;"),
        new APICall(-0x82, "TFN_DEL_MTX", "ER del_mtx ( ID mtxid ) ;"),
        new APICall(-0x83, "TFN_UNL_MTX", "ER unl_mtx ( ID mtxid ) ;"),
        new APICall(-0x85, "TFN_LOC_MTX", "ER loc_mtx ( ID mtxid ) ;"),
        new APICall(-0x86, "TFN_PLOC_MTX", "ER ploc_mtx ( ID mtxid ) ;"),
        new APICall(-0x87, "TFN_TLOC_MTX", "ER tloc_mtx ( ID mtxid, TMO tmout ) ;"),
        new APICall(-0x88, "TFN_REF_MTX", "ER ref_mtx ( ID mtxid, T_RMTX*pk_rmtx ) ;"),
        new APICall(-0x89, "TFN_CRE_MBF", "ER cre_mbf ( ID mbfid, T_CMBF *pk_cmbf ) ;"),
        new APICall(-0x8a, "TFN_DEL_MBF", "ER del_mbf ( ID mbfid ) ;"),
        new APICall(-0x8d, "TFN_SND_MBF", "ER snd_mbf ( ID mbfid, VP msg, UINT msgsz ) ;"),
        new APICall(-0x8e, "TFN_PSND_MBF", "ER psnd_mbf ( ID mbfid, VP msg, UINT msgsz ) ;"),
        new APICall(-0x8f, "TFN_TSND_MBF", "ER tsnd_mbf ( ID mbfid, VP msg, UINT msgsz, TMO tmout ) ;"),
        new APICall(-0x91, "TFN_RCV_MBF", "ER_UINT rcv_mbf ( ID mbfid,VP msg ) ;"),
        new APICall(-0x92, "TFN_PRCV_MBF", "ER_UINT prcv_mbf ( ID mbfid, VP msg ) ;"),
        new APICall(-0x93, "TFN_TRCV_MBF", "ER_UINT trcv_mbf ( ID mbfid, VP msg, TMO tmout ) ;"),
        new APICall(-0x94, "TFN_REF_MBF", "ER ref_mbf ( ID mbfid, T_RMBF *pk_rmbf ) ;"),
        new APICall(-0x95, "TFN_CRE_POR", "ER cre_por ( ID porid, T_CPOR *pk_cpor );"),
        new APICall(-0x96, "TFN_DEL_POR", "ER del_por ( ID porid ) ;"),
        new APICall(-0x97, "TFN_CAL_POR", "ER_UINT cal_por ( ID porid, RDVPTN calptn, VP msg, UINT cmsgsz) ;"),
        new APICall(-0x98, "TFN_TCAL_POR", "ER_UINT tcal_por ( ID porid, RDVPTN calptn, VP msg, UINT cmsgsz, TMO tmout);"),
        new APICall(-0x99, "TFN_ACP_POR", "ER_UINT acp_por ( ID porid, RDVPTN acpptn, RDVNO *p_rdvno, VP msg);"),
        new APICall(-0x9a, "TFN_PACP_POR", "ER_UINT pacp_por ( ID porid, RDVPTN acpptn, RDVNO *p_rdvno, VP msg ) ;"),
        new APICall(-0x9b, "TFN_TACP_POR", "ER_UINT tacp_por ( ID porid, RDVPTN acpptn, RDVNO *p_rdvno, VP msg, TMO tmout ) ;"),
        new APICall(-0x9c, "TFN_FWD_POR", "ER fwd_por (ID porid, RDVPTN calptn, RDVNO rdvno, VP msg, UINT cmsgsz ) ;"),
        new APICall(-0x9d, "TFN_RPL_RDV", "ER rpl_rdv ( RDVNO rdvno, VP msg, UINT rmsgsz ) ;"),
        new APICall(-0x9e, "TFN_REF_POR", "ER ref_por ( ID porid, T_RPOR *pk_rpor ) ;"),
        new APICall(-0x9f, "TFN_REF_RDV", "ER ref_rdv ( RDVNO rdvno, T_RRDV *pk_rrdv ) ;"),
        new APICall(-0xa1, "TFN_CRE_MPL", "ER cre_mpl ( ID mplid, T_CMPL*pk_cmpl ) ;"),
        new APICall(-0xa2, "TFN_DEL_MPL", "ER del_mpl ( ID mplid ) ;"),
        new APICall(-0xa3, "TFN_REL_MPL", "ER rel_mpl ( ID mplid, VP blk ) ;"),
        new APICall(-0xa5, "TFN_GET_MPL", "ER get_mpl ( ID mplid, UINT blksz, VP *p_blk ) ;"),
        new APICall(-0xa6, "TFN_PGET_MPL", "ER pget_mpl ( ID mplid, UINT blksz, VP *p_blk ) ;"),
        new APICall(-0xa7, "TFN_TGET_MPL", "ER tget_mpl ( ID mplid, UINT blksz, VP *p_blk, TMO tmout ) ;"),
        new APICall(-0xa8, "TFN_REF_MPL", "ER ref_mpl ( ID mplid, T_RMPL*pk_rmpl ) ;"),
        new APICall(-0xa9, "TFN_CRE_ALM", "ER cre_alm( ID almid, T_CALM *pk_calm ) ;"),
        new APICall(-0xaa, "TFN_DEL_ALM", "ER del_alm( ID almid ) ;"),
        new APICall(-0xab, "TFN_STA_ALM", "ER sta_alm( ID almid, RELTIM almtim) ;"),
        new APICall(-0xac, "TFN_STP_ALM", "ER stp_alm( ID almid ) ;"),
        new APICall(-0xad, "TFN_REF_ALM", "ER ref_alm( ID almid, T_RALM *pk_ralm);"),
        new APICall(-0xb1, "TFN_DEF_OVR", "ER def_ovr ( T_DOVR *pk_dovr) ;"),
        new APICall(-0xb2, "TFN_STA_OVR", "ER sta_ovr ( ID tskid, OVRTIM ovrtim) ;"),
        new APICall(-0xb3, "TFN_STP_OVR", "ER stp_ovr ( ID tskid ) ;"),
        new APICall(-0xb4, "TFN_REF_OVR", "ER ref_ovr ( ID tskid, T_ROVR *pk_rovr ) ;"),
        new APICall(-0xc1, "TFN_ACRE_TSK", "ER_ID acre_tsk ( T_CTSK *pk_ctsk ) ;"),
        new APICall(-0xc2, "TFN_ACRE_SEM", "ER_ID acre_sem(T_CSEM *pk_csem) ;"),
        new APICall(-0xc3, "TFN_ACRE_FLG", "ER_ID acre_flg ( T_CFLG *pk_cflg ) ;"),
        new APICall(-0xc4, "TFN_ACRE_DTQ", "ER_ID acre_dtq ( T_CDTQ *pk_cdtq ) ;"),
        new APICall(-0xc5, "TFN_ACRE_MBX", "ER_ID acre_mbx ( T_CMBX *pk_cmbx ) ;"),
        new APICall(-0xc6, "TFN_ACRE_MTX", "ER_ID acre_mtx ( T_CMTX *pk_cmtx ) ;"),
        new APICall(-0xc7, "TFN_ACRE_MBF", "ER_ID acre_mbf ( T_CMBF *pk_cmbf ) ;"),
        new APICall(-0xc8, "TFN_ACRE_POR", "ER_ID acre_por ( T_CPOR *pk_cpor ) ;"),
        new APICall(-0xc9, "TFN_ACRE_MPF", "ER_ID acre_mpf ( T_CMPF *pk_cmpf ) ;"),
        new APICall(-0xca, "TFN_ACRE_MPL", "ER_ID acre_mpl ( T_CMPL *pk_cmpl ) ;"),
        new APICall(-0xcb, "TFN_ACRE_CYC", "ER_ID acre_cyc ( T_CCYC *pk_ccyc ) ;"),
        new APICall(-0xcc, "TFN_ACRE_ALM", "ER_ID acre_alm ( T_CALM *pk_calm) ;"),
        new APICall(-0xcd, "TFN_ACRE_ISR", "ER_ID acre_isr ( T_CISR *pk_cisr ) ;"),
    };

    public static String toByteString(int val) {
        StringBuilder cbuf = new StringBuilder();
        ByteBuffer bb = ByteBuffer.allocate(4); 
        bb.putInt(val); 
        for (byte b : bb.array()) {
            cbuf.append(String.format("\\x%02x", b & 0xff));
        }
        return cbuf.toString();
    }

    public void run() throws Exception {
        for (APICall call : apis) {
            String argList = call.proto.substring(call.proto.indexOf("(") + 1);
            argList = argList.substring(0, argList.indexOf(")"));
            int numArgs = argList.length() - argList.replace(",", "").length() + 1;
            if (argList.isEmpty())
                numArgs = 0;
            int apiId = ((call.id << 8) & 0xffffffff) | numArgs;

            String fnName = call.proto.substring(call.proto.indexOf(" ") + 1);
            fnName = fnName.substring(0, fnName.indexOf("("));
            fnName = fnName.replaceAll("\\s+","");

            Address[] address = findBytes(toAddr(0), toByteString(swap32(apiId)), 1, 4);
            if (address.length == 1) {
                // println("Found: " + call.tfn);
                clearListing​(address[0], address[0].add(4));
                createDWord​(address[0]);
                Symbol sym = getSymbolAt​(address[0]);
                if (sym != null) {
                    // rename the symbol
                    sym.setName(call.tfn, SourceType.USER_DEFINED);
                }
                else {
                    // create a label if we don't have one
                    sym = createLabel(address[0], call.tfn, true);
                }
                if (sym.getReferenceCount() == 1) {
                    Address fnAddress = sym.getReferences()[0].getFromAddress();
                    Function fn = getFunctionBefore(fnAddress);
                    if (fn != null) {
                        fn.setName(fnName, SourceType.USER_DEFINED);
                        println("Found: " + fnName);
                    }
                    else {
                        println("No function at: " + fnAddress);
                    }
                }
                else if (!sym.hasReferences()) {
                    println("Couldn't find function for: " + call.tfn);
                }
                else {
                    println("More than one reference for: " + call.tfn);
                }
            }
            else if (address.length == 0) {
                println("Couldn't find: " + call.tfn + " " + toByteString(apiId));
            }
            else {
                println("Found more than 1 match for: " + call.tfn);
            }
        }
    }

}
