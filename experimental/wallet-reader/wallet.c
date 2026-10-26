/* D110_M 4.31 only. Local SELECT and fixed INR 1.00 transaction experiment.
 * No acquirer/issuer connection, tag writes, or persistent application state. */
typedef unsigned char u8;
typedef unsigned int u32;
#define FN(a,t) ((t)(0x01010001u + (a)))
#define INLINE static __attribute__((always_inline)) inline
#define LOCAL static __attribute__((noinline))
#define BYTE(a) (*(volatile u8 *)(a))
typedef int (*Dispatch)(const u8 *, u8 *, u8 *);
INLINE void feed(void) { FN(0x2100,void (*)(void))(); }
INLINE u32 now(void) { return FN(0x78c8,u32 (*)(void))(); }
INLINE int elapsed(u32 t,u32 ms) { return FN(0x78d4,int (*)(u32,u32))(t,ms); }
INLINE u32 frame_ms(u32 exponent) { return FN(0xfc,u32 (*)(u32,u32))((302u<<exponent)+999,1000); }
INLINE void wr(u32 reg,u32 val) { FN(0x7214,void (*)(u32,u32,u32))(0,reg,val); }
INLINE u8 rd(u32 reg) { u8 v=0; FN(0x3c60,void (*)(u32,u32,u8 *))(0,reg,&v); return v; }
INLINE void field(u32 mode) { FN(0x7252,void (*)(u32,u32))(0,mode); }
INLINE void crc_on(u32 on) {
    FN(0x7324,void (*)(u32,u32))(0,on);
    FN(0x72a0,void (*)(u32,u32))(0,on);
}

/* Mirrors stock 0x2cf8, adding a software deadline, watchdog servicing,
 * and a capacity check BEFORE reading the FIFO. CRC is stripped by hardware
 * when enabled, as in stock page reads. No chip identity is assumed. */
LOCAL int exchange(const u8 *tx,u32 tn,u32 bits,u8 *rx,u8 *rn,u32 ms,u8 *err) {
    *rn=0; *err=0;
    if (!tn || tn>62 || !ms || ms>1000) return 8;
    FN(0x72b8,int (*)(u32,u32))(0,ms);
    wr(1,0); wr(0x0a,0x80); wr(3,0); wr(2,0x80); wr(4,0x7f);
    wr(0x2a,rd(0x2a)|0x80);
    for(u32 i=0;i<tn;i++) wr(9,tx[i]);
    wr(1,0x0c); wr(0x0d,0x80|bits);
    u32 start=now(); int status=3;
    for(u32 polls=0;polls<200000;polls++) {
        feed(); u8 irq=rd(4);
        if(irq&2) { *err=rd(6); status=5; break; }
        if(irq&0x20) {
            u8 n=rd(0x0a)&0x7f;
            if(n>64 || (rd(0x0c)&7)) { status=6; break; }
            for(u32 i=0;i<n;i++) rx[i]=rd(9);
            *rn=n; status=n?0:6; break;
        }
        if((irq&1) || elapsed(start,ms+5)) break;
    }
    wr(0x0d,0); wr(1,0); wr(4,0x7f);
    return status;
}

INLINE int busy(void) {
    u8 s=BYTE(0x203a4);
    return BYTE(0x207d0)!=2 || (s!=0 && s!=7) || BYTE(0x21cf1) ||
        BYTE(0x21cec) || BYTE(0x204d5) || BYTE(0x207f0)==1 ||
        BYTE(0x207c8) || BYTE(0x207ec);
}

/* Payload: WA,1,status,stage,hardware_error,ATQA[2],SAK,UIDlen,UID[10],
 * ATSlen,ATS[32],APDUlen,APDU[0..180]. Stages 1 WUPA,2 anticollision,
 * 3 SELECT,4 RATS,5 APDU. Failed stages retain earlier observations. */
typedef struct {u32 fsc,timeout,bn;u8 diag[8];} Link;
LOCAL int activate(Link *link,u8 *p) {
    for(u32 i=0;i<8;i++)link->diag[i]=0;
    u8 tx[64],rx[64],n=0; int status=0; u32 uidn=0;
    field(0); field(3); wr(8,rd(8)&~8u); crc_on(0);
    p[4]=1; tx[0]=0x52;
    status=exchange(tx,1,7,rx,&n,5,p+5);
    if(status) goto done;
    if(n!=2) { status=6; goto done; }
    p[6]=rx[0]; p[7]=rx[1];
    for(u32 level=0;level<3;level++) {
        p[4]=2; crc_on(0); tx[0]=0x93+2*level; tx[1]=0x20;
        status=exchange(tx,2,0,rx,&n,5,p+5);
        if(status) goto done;
        if(n!=5 || (rx[0]^rx[1]^rx[2]^rx[3])!=rx[4]) { status=6; goto done; }
        u32 cascade=rx[0]==0x88;
        if((level==2 && cascade) || uidn+4-cascade>10) { status=6; goto done; }
        for(u32 i=cascade;i<4;i++) p[10+uidn++]=rx[i];
        p[9]=uidn; tx[1]=0x70;
        for(u32 i=0;i<5;i++) tx[i+2]=rx[i];
        p[4]=3; crc_on(1);
        status=exchange(tx,7,0,rx,&n,5,p+5);
        if(status) goto done;
        if(n!=1 || (!!(rx[0]&4))!=cascade) { status=6; goto done; }
        p[8]=rx[0];
        if(!(rx[0]&4)) break;
    }
    if(p[8]&4) { status=6; goto done; }
    if(!(p[8]&0x20)) { status=4; goto done; }
    p[4]=4; tx[0]=0xe0; tx[1]=0x50; /* FSD=64, CID=0 */
    status=exchange(tx,2,0,rx,&n,100,p+5);
    if(status) goto done;
    if(!n || n>32 || rx[0]!=n) { status=6; goto done; }
    p[20]=n; for(u32 i=0;i<n;i++) p[21+i]=rx[i];
    u32 fsc=32, fwi=4, sfgi=0, ix=2;
    if(n>1) {
        u32 fsci=rx[1]&15;
        if(fsci>8) { status=6; goto done; }
        fsc=fsci<5 ? 16+8*fsci : fsci==5 ? 64 : fsci==6 ? 96 : fsci==7 ? 128 : 256;
        if(rx[1]&0x80) { status=6; goto done; }
        if(rx[1]&0x10) { if(ix>=n) {status=6;goto done;} ix++; }
        if(rx[1]&0x20) { if(ix>=n) {status=6;goto done;} fwi=rx[ix]>>4;sfgi=rx[ix++]&15; }
        if(rx[1]&0x40) { if(ix>=n) {status=6;goto done;} ix++; }
    }
    if(fwi>11 || sfgi>11) {status=8;goto done;}
    u32 timeout=frame_ms(fwi)+2;
    if(sfgi) {u32 t=now(),ms=frame_ms(sfgi);while(!elapsed(t,ms)) feed();}
    link->fsc=fsc>64?64:fsc;link->timeout=timeout;link->bn=0;
    return 0;
done:
    return status;
}

/* One APDU, with persistent block numbering across the entire RF session. */
LOCAL int apdu_exchange(Link *link,const u8 *apdu,u32 size,u8 *out,u32 capacity,u32 *length,u8 *err) {
    u8 tx[64],rx[64],n=0;
    u32 sent=0,bn=link->bn,total=0,waiting=0,start=now(),ms=link->timeout;
    u32 chunk=size<(link->fsc-3)?size:(link->fsc-3);
    *length=0;
    link->diag[0]=0;
    tx[0]=2|bn|(chunk<size?0x10:0);for(u32 i=0;i<chunk;i++)tx[1+i]=apdu[i];
    u32 tn=1+chunk;
    for(u32 frames=0;frames<64;frames++) {
        if(elapsed(start,8000)){link->diag[0]=5;return 3;}
        link->diag[1]=tx[0];link->diag[2]=0;link->diag[3]=tn;link->diag[4]=0;
        link->diag[5]=bn;link->diag[6]=(!waiting && sent+chunk<size)?1:2;link->diag[7]=frames;
        int status=exchange(tx,tn,0,rx,&n,ms,err);
        link->diag[4]=n;if(n)link->diag[2]=rx[0];
        if(status){link->diag[0]=1;return status;}
        ms=link->timeout;
        if(n==2 && rx[0]==0xf2 && rx[1]>=1 && rx[1]<=59) {
            ms=link->timeout*rx[1];if(ms>1000)return 8;
            tx[0]=0xf2;tx[1]=rx[1];tn=2;continue;
        }
        if(!waiting && sent+chunk<size) {
            /* ISO14443-4 PCD rule: PICC R(ACK) echoes the accepted I-block
             * number. Toggle AFTER accepting that acknowledgement. This
             * differs from the PCD's ACK during PICC response chaining. */
            if(n!=1 || rx[0]!=(0xa2|bn)){link->diag[0]=2;return 6;}
            sent+=chunk;bn^=1;chunk=size-sent;
            if(chunk>link->fsc-3)chunk=link->fsc-3;
            tx[0]=2|bn|(sent+chunk<size?0x10:0);
            for(u32 i=0;i<chunk;i++)tx[1+i]=apdu[sent+i];
            tn=1+chunk;continue;
        }
        if(!n || (rx[0]&0xee)!=2 || (rx[0]&1)!=bn){link->diag[0]=3;return 6;}
        if(total+n-1>capacity){link->diag[0]=4;return 7;}
        for(u32 i=1;i<n;i++)out[total++]=rx[i];
        *length=total;
        if(!(rx[0]&0x10)) {link->bn=bn^1;return total>=2?0:6;}
        bn^=1;tx[0]=0xa2|bn;tn=1;waiting=1;
    }
    link->diag[0]=5;return 8;
}

LOCAL int probe(const u8 *aid,u32 alen,u8 *p) {
    Link link;int status=activate(&link,p);
    if(!status) {
        u8 apdu[22];u32 size=alen?alen:14,n=0;
        apdu[0]=0;apdu[1]=0xa4;apdu[2]=4;apdu[3]=0;apdu[4]=size;
        if(alen) {for(u32 i=0;i<alen;i++)apdu[5+i]=aid[i];}
        else {
            apdu[5]='2';apdu[6]='P';apdu[7]='A';apdu[8]='Y';apdu[9]='.';
            apdu[10]='S';apdu[11]='Y';apdu[12]='S';apdu[13]='.';
            apdu[14]='D';apdu[15]='D';apdu[16]='F';apdu[17]='0';apdu[18]='1';
        }
        apdu[5+size]=0;p[4]=5;
        status=apdu_exchange(&link,apdu,size+6,p+54,180,&n,p+5);p[53]=n;
    }
    field(0);return status;
}

/* Bounded BER-TLV traversal. Validate the entire tree and reject duplicate
 * requested tags, indefinite lengths, truncation and excessive nesting. */
LOCAL int find_tag(const u8 *data,u32 size,u32 wanted,const u8 **value,u32 *length) {
    u32 ends[8],depth=0,i=0,end=size,found=0;
    *value=data;*length=0;
    while(i<end || depth) {
        if(i==end) {end=ends[--depth];continue;}
        u8 first=data[i++];u32 tag=first;
        if(first==0 || first==255)continue;
        if((first&31)==31) {
            u32 count=0;u8 b;
            do {if(i>=end || count++>=3)return 6;b=data[i++];tag=(tag<<8)|b;}while(b&128);
        }
        if(i>=end)return 6;
        u32 len=data[i++];
        if(len&128) {
            u32 count=len&127;len=0;
            if(!count || count>2 || count>end-i)return 6;
            while(count--)len=(len<<8)|data[i++];
        }
        if(len>end-i)return 6;
        if(tag==wanted) {if(found++)return 6;*value=data+i;*length=len;}
        if(first&32) {
            if(depth>=8)return 6;ends[depth++]=end;end=i+len;
        } else i+=len;
    }
    return 0;
}

/* Fixed local test: INR 1.00, India; normal CDCVM requested, no bypass,
 * transit or deferred-authorization bits. No ODA/CVM success is invented.
 * Unknown DOL fields receive zero bytes and are counted in the report. */
LOCAL int fill_dol(const u8 *dol,u32 n,const u8 *params,u8 *out,u32 *size,u8 *unknown) {
    u32 i=0,total=0;
    while(i<n) {
        u32 tag=dol[i++];
        if((tag&31)==31) {
            u32 count=0;u8 b;
            do {if(i>=n || count++>=3)return 6;b=dol[i++];tag=(tag<<8)|b;}while(b&128);
        }
        if(i>=n)return 6;
        u32 len=dol[i++];if(!len || total+len>96)return 7;
        u8 value[8];u32 expected=0,numeric=0;
        for(u32 j=0;j<8;j++)value[j]=0;
        if(tag==0x9f02) {expected=6;numeric=1;value[4]=1;}
        else if(tag==0x9f03) {expected=6;numeric=1;}
        else if(tag==0x9f1a || tag==0x5f2a) {expected=2;numeric=1;value[0]=3;value[1]=0x56;}
        else if(tag==0x9a) {expected=3;numeric=1;for(u32 j=0;j<3;j++)value[j]=params[j];}
        else if(tag==0x9f37) {expected=4;for(u32 j=0;j<4;j++)value[j]=params[3+j];}
        else if(tag==0x9c) {expected=1;numeric=1;}
        else if(tag==0x9f1d) {expected=8;value[0]=4;value[1]=0x80;value[2]=0xa0;}
        else if(tag==0x95) {expected=5;value[0]=0x80;value[2]=0x80;value[3]=0x80;}
        else if(tag==0x9f35) {expected=1;numeric=1;value[0]=0x22;}
        else if(tag==0x9f33) {expected=3;value[0]=0x20;}
        else if(tag==0x9f34) {expected=3;value[0]=0x3f;}
        else if(tag==0x9f09) {expected=2;value[1]=2;}
        else if(tag==0x9f21) {expected=3;numeric=1;}
        else if(tag==0x9f40) {expected=5;value[0]=0x80;}
        else if(tag==0x9f1b) {expected=4;}
        else {if(*unknown<255)(*unknown)++;}
        for(u32 j=0;j<len;j++) {
            u32 k=j;
            if(numeric) {
                if(len>expected)k=j>=len-expected?j-(len-expected):8;
                else k=j+expected-len;
            }
            out[total+j]=(k<expected && k<8)?value[k]:0;
        }
        total+=len;
    }
    *size=total;return 0;
}

LOCAL int cryptogram(const u8 *data,u32 size,u8 *p) {
    const u8 *v;u32 n;int status;
    if(size>=2 && data[0]==0x80) {
        if(data[1]!=size-2 || size<13 || size>45)return 6;
        p[14]=data[2];p[15]=data[3];p[16]=data[4];
        for(u32 i=0;i<8;i++)p[17+i]=data[5+i];
        p[25]=size-13;for(u32 i=13;i<size;i++)p[26+i-13]=data[i];
    } else {
        status=find_tag(data,size,0x9f27,&v,&n);if(status || n!=1)return 6;p[14]=v[0];
        status=find_tag(data,size,0x9f36,&v,&n);if(status || n!=2)return 6;p[15]=v[0];p[16]=v[1];
        status=find_tag(data,size,0x9f26,&v,&n);if(status || n!=8)return 6;
        for(u32 i=0;i<8;i++)p[17+i]=v[i];
        status=find_tag(data,size,0x9f10,&v,&n);if(status || n>32)return 6;
        p[25]=n;for(u32 i=0;i<n;i++)p[26+i]=v[i];
    }
    if((p[14]&0xc0)==0xc0)return 6;
    p[6]|=4;return 0;
}

/* WT v1 summary only: never return PAN/track data from records. One GPO,
 * up to 16 AFL records and at most ONE GENERATE AC, all in one RF session. */
LOCAL int transaction(const u8 *params,u8 *p) {
    u8 meta[54],apdu[104],response[512],afl[32],cdol[64];
    u32 size,n=0,afln=0,cdoln=0,afli=0,record=0,start=now();
    Link link;for(u32 i=0;i<54;i++)meta[i]=0;
    int status=activate(&link,meta);
    p[4]=meta[4];p[5]=meta[5];if(status)goto done;
    apdu[0]=0;apdu[1]=0xa4;apdu[2]=4;apdu[3]=0;apdu[4]=7;
    apdu[5]=0xa0;apdu[6]=0;apdu[7]=0;apdu[8]=0;apdu[9]=4;
    apdu[10]=0x10;apdu[11]=0x10;apdu[12]=0;size=13;p[4]=5;
    for(u32 step=0;step<20;step++) {
        if(elapsed(start,30000)) {status=3;goto done;}
        if(p[4]==6)p[6]|=1;
        if(p[4]==8) {if(p[6]&2){status=8;goto done;}p[6]|=2;}
        p[9]++;
        p[7]=p[8]=0;
        status=apdu_exchange(&link,apdu,size,response,512,&n,p+5);
        if(status)goto done;
        p[7]=response[n-2];p[8]=response[n-1];
        if(p[7]!=0x90 || p[8]!=0) {status=9;goto done;}
        n-=2;
        const u8 *v;u32 len;
        if(p[4]==5) {
            status=find_tag(response,n,0x9f38,&v,&len);if(status)goto done;
            if(len>32) {status=7;goto done;}
            p[156]=len;for(u32 i=0;i<len;i++)p[157+i]=v[i];
            u32 dn=0;status=fill_dol(v,len,params,apdu+7,&dn,p+11);if(status)goto done;
            apdu[0]=0x80;apdu[1]=0xa8;apdu[2]=0;apdu[3]=0;
            apdu[4]=dn+2;apdu[5]=0x83;apdu[6]=dn;apdu[7+dn]=0;
            size=dn+8;p[4]=6;continue;
        }
        if(p[4]==6) {
            if(n>=4 && response[0]==0x80) {
                if(response[1]!=n-2){status=6;goto done;}
                p[12]=response[2];p[13]=response[3];v=response+4;len=n-4;
            } else {
                status=find_tag(response,n,0x9f26,&v,&len);if(status)goto done;
                if(len) {status=cryptogram(response,n,p);goto done;}
                status=find_tag(response,n,0x82,&v,&len);if(status || len!=2){status=6;goto done;}
                p[12]=v[0];p[13]=v[1];
                status=find_tag(response,n,0x94,&v,&len);if(status)goto done;
            }
            if(!len || len>32 || (len&3)){status=6;goto done;}
            afln=len;p[58]=len;u32 records=0;
            for(u32 i=0;i<len;i++)afl[i]=p[59+i]=v[i];
            for(u32 i=0;i<len;i+=4) {
                if((afl[i]&7) || afl[i]<8 || afl[i]>240 || !afl[i+1] ||
                    afl[i+1]>afl[i+2] || afl[i+3]>afl[i+2]-afl[i+1]+1){status=6;goto done;}
                records+=afl[i+2]-afl[i+1]+1;
            }
            if(records>16){status=8;goto done;}
            record=afl[1];
        } else if(p[4]==7) {
            p[10]++;
            status=find_tag(response,n,0x8c,&v,&len);if(status)goto done;
            if(len) {
                if(cdoln || len>64){status=6;goto done;}
                cdoln=len;p[91]=len;for(u32 i=0;i<len;i++)cdol[i]=p[92+i]=v[i];
            }
            record++;
            if(record>afl[afli+2]) {afli+=4;if(afli<afln)record=afl[afli+1];}
        } else if(p[4]==8) {status=cryptogram(response,n,p);goto done;}
        if(afli<afln) {
            apdu[0]=0;apdu[1]=0xb2;apdu[2]=record;apdu[3]=afl[afli]|4;apdu[4]=0;
            size=5;p[4]=7;continue;
        }
        if(!cdoln){status=10;goto done;}
        u32 dn=0;status=fill_dol(cdol,cdoln,params,apdu+5,&dn,p+11);if(status)goto done;
        apdu[0]=0x80;apdu[1]=0xae;apdu[2]=0x80;apdu[3]=0;apdu[4]=dn;apdu[5+dn]=0;
        size=dn+6;p[4]=8;
    }
    status=8;
done:
    for(u32 i=0;i<8;i++)p[189+i]=link.diag[i];
    field(0);return status;
}

__attribute__((used))
int wallet_dispatch(const u8 *request,u8 *output,u8 *output_len) {
    if(request[3]!=0xf2) return ((Dispatch)(PREV_DISPATCH|1u))(request,output,output_len);
    u8 *p=output+4;for(u32 i=0;i<234;i++)p[i]=0;
    p[0]='W';p[1]='A';p[2]=1;p[3]=1;
    u32 transaction_reply=0;
    if(request[4]==1 && request[5]==0) p[3]=0x10;
    else if(request[4]==1 && request[5]==1) {p[1]='T';p[3]=0x11;transaction_reply=1;}
    else if(request[4]==12 && request[5]=='T' && request[6]=='X' && request[7]=='N' &&
            request[8]==1 && request[9]==0xa5) {
        p[1]='T';transaction_reply=1;
        u32 valid=1;
        for(u32 i=10;i<13;i++)if((request[i]&15)>9 || (request[i]>>4)>9)valid=0;
        if(!request[11] || request[11]>0x12 || !request[12] || request[12]>0x31)valid=0;
        if(valid)p[3]=busy()?2:transaction(request+10,p);
    }
    else if(request[4]>=8 && request[4]<=24 && request[5]=='W' && request[6]=='A' &&
        request[7]=='L' && request[8]=='L' && request[9]=='E' && request[10]=='T' &&
        request[11]==1 && request[12]==0xa5) {
        u32 n=request[4]-8;
        if(n==0 || (n>=5 && n<=16)) p[3]=busy()?2:probe(request+13,n,p);
    }
    u32 size=transaction_reply?198:54+p[53];u8 sum=0xf3^size;
    for(u32 i=0;i<size;i++)sum^=p[i];
    output[0]=output[1]=0x55;output[2]=0xf3;output[3]=size;
    output[4+size]=sum;output[5+size]=output[6+size]=0xaa;
    *output_len=size+7;return 1;
}
