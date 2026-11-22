import struct
FREESECT=0xFFFFFFFF; ENDOFCHAIN=0xFFFFFFFE; FATSECT=0xFFFFFFFD; NOSTREAM=0xFFFFFFFF
MINI_CUTOFF=4096; MINI_SECTOR=64
HEADER_SIGNATURE=bytes([0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1])
def _pad(b,n):
    return b+bytes((-len(b))%n)
def _u16(s):
    return s.encode("utf-16-le") if isinstance(s,str) else s
def guid(s):
    p=s.split("-")
    return struct.pack("<IHH",int(p[0],16),int(p[1],16),int(p[2],16))+bytes.fromhex(p[3]+p[4])
FMTID_SI=guid("F29F85E0-4FF9-1068-AB91-08002B27B3D9")
FMTID_DSI=guid("D5CDD502-2E9C-101B-9397-08002B2CF9AE")
def _typed(value):
    if isinstance(value,bool): return 0x000B
    if isinstance(value,int): return 0x0003
    if isinstance(value,str): return 0x001E
    raise TypeError(type(value))

def _value_bytes(ptype,value):
    if ptype==0x0003: return struct.pack("<i",value)
    if ptype==0x000B: return struct.pack("<i",1 if value else 0)
    if ptype==0x001E:
        data=value.encode("cp1252","replace")+bytes(1)
        return _pad(struct.pack("<I",len(data))+data,4)
    raise TypeError(ptype)

def property_set_stream(fmtid_guid, props):
    if not any(pid==1 for pid,_ in props):
        props=[(1,1252)]+list(props)
    n=len(props); tl=8*n; disk=b""; metas=[]
    for pid,value in props:
        metas.append((pid,8+tl+len(disk)))
        ptype=_typed(value)
        disk+=_pad(struct.pack("<I",ptype)+_value_bytes(ptype,value),4)
    sec=8+tl+len(disk)
    raw=bytearray(48+4+tl+len(disk)+8)
    struct.pack_into("<HHHH",raw,0,0xFEFF,0,0,0)
    struct.pack_into("<I",raw,24,1)
    raw[28:44]=fmtid_guid
    struct.pack_into("<I",raw,44,48)
    struct.pack_into("<I",raw,48,sec)
    struct.pack_into("<I",raw,52,n)
    for i,(pid,off) in enumerate(metas):
        struct.pack_into("<II",raw,56+8*i,pid,off)
    start=56+tl; raw[start:start+len(disk)]=disk
    return _pad(bytes(raw),4)
def compobj_stream(clsid, display_name, typename="Package"):
    out=struct.pack("<I",0x00000201)+clsid
    tn=typename.encode("cp1252","replace")+bytes(1)
    dn=display_name.encode("cp1252","replace")+bytes(1)
    out+=struct.pack("<I",len(tn))+tn
    out+=struct.pack("<I",len(dn))+dn
    out+=struct.pack("<I",0)
    return out
def directory_entry(name, etype, color, left, right, child, start, size, clsid=bytes(16), state=0):
    if name=="":
        nb=bytes(64); nlen=2
    else:
        raw=_u16(name)+bytes(2)
        nb=_pad(raw,64); nlen=len(raw)
    out=nb+struct.pack("<HBB",nlen,etype,color)
    out+=struct.pack("<III",left,right,child)+clsid
    out+=struct.pack("<I",state)+struct.pack("<QQ",0,0)
    out+=struct.pack("<III",start,size,0)
    assert len(out)==128
    return out
def build_cfb(streams, root_clsid=bytes(16)):
    names=list(streams.keys())
    mini=b""; mini_entries=[]; spans=[]
    for nm in names:
        body=streams[nm]
        start=len(mini)//MINI_SECTOR
        padded=_pad(body,MINI_SECTOR)
        mini+=padded
        count=len(padded)//MINI_SECTOR
        spans.append((start,count))
        mini_entries.append((nm,start,len(body)))
    nmini=len(mini)//MINI_SECTOR
    minifat=[FREESECT]*128
    for start,count in spans:
        for k in range(count):
            idx=start+k
            minifat[idx]=ENDOFCHAIN if k==count-1 else idx+1
    minifat_blob=b"".join(struct.pack("<I",x) for x in minifat)
    root_blob=_pad(mini,512)
    root_sectors=max(1,len(root_blob)//512)
    dir_sectors=(1+len(names)+3)//4
    regular=1+root_sectors+dir_sectors
    f=1
    while f*128 < regular+f:
        f+=1
    minifat_start=0; root_start=1; dir_start=1+root_sectors; fat_start=dir_start+dir_sectors
    fat=[FREESECT]*(f*128)
    fat[minifat_start]=ENDOFCHAIN
    for k in range(root_sectors):
        fat[root_start+k]=ENDOFCHAIN if k==root_sectors-1 else root_start+k+1
    for k in range(dir_sectors):
        fat[dir_start+k]=ENDOFCHAIN if k==dir_sectors-1 else dir_start+k+1
    for k in range(f):
        fat[fat_start+k]=FATSECT
    difat=[fat_start+k for k in range(f)]+[FREESECT]*(109-f)
    return _emit(minifat_blob,root_blob,mini_entries,len(mini),root_clsid,dir_sectors,root_sectors,minifat_start,root_start,dir_start,f,fat,difat)
def _emit(minifat_blob,root_blob,mini_entries,root_size,root_clsid,dir_sectors,root_sectors,minifat_start,root_start,dir_start,f,fat,difat):
    entries=[directory_entry("",5,0,NOSTREAM,NOSTREAM,1 if mini_entries else NOSTREAM,root_start,root_size,root_clsid)]
    n=len(mini_entries)
    for idx,(nm,start,size) in enumerate(mini_entries):
        right=NOSTREAM if idx==n-1 else idx+2
        entries.append(directory_entry(nm,2,0,NOSTREAM,right,NOSTREAM,start,size))
    while len(entries)<dir_sectors*4:
        entries.append(bytes(128))
    dirblob=b"".join(entries)
    fatblob=_pad(b"".join(struct.pack("<I",x) for x in fat),512*f)
    h=bytearray(512)
    h[0:8]=HEADER_SIGNATURE
    struct.pack_into("<HHHH",h,24,0x003E,0x0003,0xFFFE,0x0009)
    struct.pack_into("<HH",h,32,6,3)
    struct.pack_into("<I",h,44,f)
    struct.pack_into("<I",h,48,dir_start)
    struct.pack_into("<I",h,52,ENDOFCHAIN)
    struct.pack_into("<I",h,56,MINI_CUTOFF)
    struct.pack_into("<I",h,60,minifat_start)
    struct.pack_into("<I",h,64,MINI_SECTOR)
    struct.pack_into("<I",h,68,ENDOFCHAIN)
    struct.pack_into("<I",h,72,0)
    for k,sect in enumerate(difat):
        struct.pack_into("<I",h,76+4*k,sect)
    return bytes(h)+minifat_blob+root_blob+dirblob+fatblob
