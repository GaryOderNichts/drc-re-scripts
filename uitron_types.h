typedef signed __int8 B;
typedef signed __int16 H;
typedef signed __int32 W;
typedef signed __int64 D;
typedef unsigned __int8 UB;
typedef unsigned __int16 UH;
typedef unsigned __int32 UW;
typedef unsigned __int64 UD;
// impl-defined:
typedef UB VB;
typedef UH VH;
typedef UW VW;
typedef UD VD;
typedef void * VP;
//------
typedef int INT;
typedef unsigned int UINT;
typedef UB BOOL;
typedef INT FN;
typedef INT ER;
typedef INT ID;
typedef UINT ATR;
typedef UINT STAT;
typedef UINT MODE;
typedef INT PRI;
typedef UINT SIZE;
typedef INT TMO;
typedef UINT RELTIM;
typedef UINT SYSTIM;
typedef INT * VP_INT;
typedef INT ER_BOOL;
typedef ID ER_ID;
typedef UINT ER_UINT;
typedef void (*FP)();
typedef UW RDVNO;
typedef UINT EXCNO;
typedef UINT INHNO;
typedef UINT INTNO;
typedef UW OVRTIM;
typedef UINT FLGPTN;
typedef UINT TEXPTN;
typedef UINT RDVPTN;

typedef void (*FP_ISR)(VP_INT exinf);
typedef void (*FP_ALM)(VP_INT exinf);
typedef void (*FP_CYC)(VP_INT exinf);
typedef void (*FP_TSK)(VP_INT exinf);
typedef void (*FP_OVR)(ID tskid, VP_INT exinf);
typedef void (*FP_EXC)(VP_INT exinf);
typedef ER_UINT (*FP_SVC)(VP_INT par1, VP_INT par2, ...);
typedef void (*FP_TEX)(TEXPTN texptn, VP_INT exinf);

// NOTE: MOST STRUCTS MAY BE MODIFIED BY THE IMPLEMENTATION

struct T_CISR {
ATR isratr; /* Interrupt service routine attribute */
VP_INT exinf; /* Interrupt service routine extended information */
INTNO intno; /* Interrupt number to which the interrupt service routine is to be attached */
FP_ISR isr; /* Interrupt service routine start address */
};
struct T_CALM {
ATR almatr; /* Alarmhandler attribute */
VP_INT exinf; /* Alarmhandler extended information */
FP_ALM almhdr; /* Alarmhandler start address */
char *name;
};
struct T_CCYC {
ATR cycatr; /* Cyclic handler attribute */
VP_INT exinf; /* Cyclic handler extended information */
FP_CYC cychdr; /* Cyclic handler start address */
RELTIM cyctim; /* Cyclic handler activation cycle */
RELTIM cycphs; /* Cyclic handler activation phase */
char *name;
};
struct T_CMPL {
ATR mplatr; /* Variable-sized memory pool attribute */
SIZE mplsz; /* Size of the variable-sizedmemorypool area (in bytes) */
VP mpl; /* Start address of the variable-sized memory pool area */
char *name;
};
struct T_CMPF {
ATR mpfatr; /* Fixed-sized memorypool attribute */
UINT blkcnt; /* Total number of available memoryblocks */
UINT blksz; /* Memoryblock size (in bytes) */
VP mpf; /* Start address of the fixed-sized memory pool area */
char *name;
};
struct T_CPOR {
ATR poratr; /* Rendezvous port attribute */
UINT maxcmsz; /* Maximum calling message size (in bytes) */
UINT maxrmsz; /* Maximum return message size (in bytes) */
char *name;
};
struct T_CMBF {
ATR mbfatr; /* Message buffer attribute */
UINT maxmsz; /* Maximum message size (in bytes) */
SIZE mbfsz; /* Size of message buffer area (in bytes) */
VP mbf; /* Start address of messagebuffer area */
char *name;
};
struct T_CMTX {
ATR mtxatr; /* Mutex attribute */
PRI ceilpri; /* Mutex ceiling priority */
};
struct T_CMBX {
ATR mbxatr; /* Mailboxattribute */
PRI maxmpri; /* Maximum message priority of the messages to be sent */
VP mprihd; /* Start address of the area for message queue headers for each message priority */
char *name;
};
struct T_CDTQ {
ATR dtqatr; /* Data queue attribute */
UINT dtqcnt; /* Capacityofthe data queue area (the number of data elements) */
VP dtq; /* Start address of the data queue area */
char *name;
};
struct T_CFLG {
ATR flgatr; /* Eventflag attribute */
FLGPTN iflgptn; /* Initial value of the eventflag bit pattern */
char *name;
};
struct T_CSEM {
ATR sematr; /* Semaphore attribute */
UINT isemcnt; /* Initial semaphore resource count */
UINT maxsem; /* Maximum semaphore resource count */
char *name;
};
struct T_CTSK {
ATR tskatr; /* Task attribute */
VP_INT exinf; /* Task extended information */
FP_TSK task; /* Task start address */
PRI itskpri; /* Task initialpriority */
SIZE stksz; /* Task stack size (in bytes)*/
VP stk; /* Base address of task stack area */
char *name;
};
struct T_ROVR {
STAT ovrstat; /* Overrun handler operational state */
OVRTIM leftotm; /* Remaining processing time */
};
struct T_DOVR {
ATR ovratr; /* Overrun handler attribute */
FP_OVR ovrhdr; /* Overrun handler start address */
};
struct T_RALM {
STAT almstat; /* Alarmhandler operational state */
RELTIM lefttim; /* Timeleft before the activation */
};
struct T_RMPL {
ID wtskid; /* ID numberof the task at the head of the variable-sized memory pool's wait queue */
SIZE fmplsz; /* Total size of free memory blocks in the variable-sized memory pool (in bytes) */
UINT fblksz; /* Maximum memoryblock size available in bytes */
};
struct T_RRDV {
ID wtskid; /* ID number of the task in the termination waiting state for the rendezvous */
};
struct T_RPOR {
ID ctskid; /* ID numberof the task at the head of the rendezvous port's call-wait queue */
ID atskid; /* ID numberof the task at the head of the rendezvous port's accept-wait queue */
};
struct T_RMBF {
ID stskid; /* ID numberof the task at the head of the message buffer's send-wait queue */
ID rtskid; /* ID numberof the task at the head of the message buffer's receive-wait queue */
UINT smsgcnt; /* The number of messagesin the message buffer */
SIZE fmbfsz; /* Size of free message buffer areain bytes, without the minimum control areas */
};
struct T_RMTX {
ID htskid; /* ID numberof the task that locks the mutex */
ID wtskid; /* ID numberof the task at the head of the mutex's wait queue */
};
struct T_RVER {
UH maker; /* Kernel makers code */
UH prid; /* Identification number of the kernel */
UH spver; /* Version number of the ITRON Specification */
UH prver; /* Version number of the kernel */
UH prno[4]; /* Management information of the kernel product */
};
struct T_RCFG {
UB IMPLEMENTATION_SPECIFIC;
};
struct T_DEXC {
ATR excatr; /* CPU exception handler attribute */
FP_EXC exchdr; /* CPU exception handler start address */
};
struct T_DSVC {
ATR svcatr; /* Extended service call attribute */
FP_SVC svcrtn; /* Extended service call routine start address */
};
struct T_RISR {
UB IMPLEMENTATION_SPECIFIC;
};
struct T_DINH {
ATR inhatr; /* Interrupt handler attribute */
FP_ISR inthdr; /* Interrupt handler start address */
char *name;
};
struct T_RSYS {
UB IMPLEMENTATION_SPECIFIC;
};
struct T_RCYC {
STAT cycstat; /* Cyclic handler operational state */
RELTIM lefttim; /* Timeleft before the next activation */
};
struct T_RMPF {
ID wtskid; /* ID numberof the task at the head of the fixed-sized memory pool's wait queue */
UINT fblkcnt; /* Number of free memory blocks in the fixed-sized memory pool */
};
struct T_MSG {
UB IMPLEMENTATION_SPECIFIC;
};
struct T_RMBX {
ID wtskid; /* ID numberof the task at the head of the mailbox's wait queue */
T_MSG * pk_msg; /* Start address of the message packet at the head of the message queue */
};
struct T_RDTQ {
ID stskid; /* ID numberof the task at the head of the data queue's send-wait queue */
ID rtskid; /* ID numberof the task at the head of the data queue's receive-wait queue */
UINT sdtqcnt; /* The number of data elements in the data queue */
};
struct T_RFLG {
ID wtskid; /* ID numberof the task at the head of the eventflag's wait queue */
FLGPTN flgptn; /* Current eventflag bit pattern */
};
struct T_RSEM {
ID wtskid; /* ID numberof the task at the head of the semaphore's wait queue */
UINT semcnt; /* Current semaphore resource count */
};
struct T_RTEX {
STAT texstat; /* Task exception handling state */
TEXPTN pndptn; /* Pendingexception code */
};
struct T_DTEX {
ATR texatr; /* Task exception handling routine attribute */
FP_TEX texrtn; /* Task exception handling routine start address */
};
struct T_RTST {
STAT tskstat; /* Task state */
STAT tskwait; /* Reason for waiting */
};
struct T_RTSK {
STAT tskstat; /* Task state */
PRI tskpri; /* Task current priority*/
PRI tskbpri; /* Task base priority */
STAT tskwait; /* Reason for waiting */
ID wobjid; /* Object ID number for which the task is waiting */
TMO lefttmo; /* Remaining time until timeout */
UINT actcnt; /* Activation request count */
UINT wupcnt; /* Wakeup request count */
UINT suscnt; /* Suspension count */
};
