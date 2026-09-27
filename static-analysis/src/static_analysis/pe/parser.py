"""Defensive PE/COFF parser for static header, section, and directory inspection."""

import math
import struct
from datetime import datetime, timezone

from static_analysis.pe.models import PeExport, PeImport, PeIndicators, PeResourceInfo, PeSection, PeSecurityInfo, PeInfo

_MACHINES={0x14c:"x86",0x8664:"x64",0x1c0:"arm",0xaa64:"arm64"}; _SUBSYSTEMS={2:"windows_gui",3:"windows_console",9:"windows_ce",10:"efi_application",14:"xbox",16:"boot_application"}; _SUSPICIOUS_SECTIONS={"upx0","upx1",".aspack",".packed","petite",".mpress"}; _SUSPICIOUS_APIS={"VirtualAlloc","VirtualProtect","WriteProcessMemory","CreateRemoteThread","NtQueryInformationProcess","IsDebuggerPresent","CheckRemoteDebuggerPresent","GetProcAddress","LoadLibraryA","LoadLibraryW","WinExec","ShellExecuteA","URLDownloadToFileA"}; _RESOURCE_NAMES={1:"cursor",2:"bitmap",3:"icon",4:"menu",5:"dialog",6:"string",10:"rcdata",14:"group_icon",16:"version",24:"manifest"}
class PeParseError(ValueError): pass

class PeParser:
    def parse(self, data: bytes) -> PeInfo:
        if len(data)<0x40 or data[:2]!=b"MZ": raise PeParseError("invalid_dos_header")
        peoff=struct.unpack_from("<I",data,0x3c)[0]
        if peoff+24>len(data) or data[peoff:peoff+4]!=b"PE\0\0": raise PeParseError("invalid_pe_header")
        machine,sections,timestamp,_,_,optsize,chars=struct.unpack_from("<HHIIIHH",data,peoff+4); opt=peoff+24
        if opt+optsize>len(data) or optsize<96: raise PeParseError("invalid_optional_header")
        magic=struct.unpack_from("<H",data,opt)[0]; is64=magic==0x20b
        if magic not in (0x10b,0x20b): raise PeParseError("unsupported_optional_header")
        entry=struct.unpack_from("<I",data,opt+16)[0]; imagebase=struct.unpack_from("<Q" if is64 else "<I",data,opt+(24 if is64 else 28))[0]; subsystem=struct.unpack_from("<H",data,opt+68)[0]
        directory_offset=opt+(112 if is64 else 96); count=min(struct.unpack_from("<I",data,opt+(108 if is64 else 92))[0],16); directories=[struct.unpack_from("<II",data,directory_offset+i*8) if directory_offset+i*8+8<=opt+optsize else (0,0) for i in range(count)]
        table=opt+optsize; parsed=[]
        for i in range(sections):
            p=table+i*40
            if p+40>len(data): raise PeParseError("truncated_section_table")
            rawname=data[p:p+8].split(b"\0",1)[0].decode("ascii","replace"); vs,va,rs,rp=struct.unpack_from("<IIII",data,p+8); ch=struct.unpack_from("<I",data,p+36)[0]; blob=data[rp:min(len(data),rp+rs)] if rp<len(data) else b""; entropy=self._entropy(blob); parsed.append(PeSection(rawname,va,vs,rs,rp,ch,entropy,bool(ch&0x20000000 and ch&0x80000000),rawname.lower() in _SUSPICIOUS_SECTIONS))
        rva=lambda value:self._rva(value,parsed)
        imports=self._imports(data,directories[1] if len(directories)>1 else (0,0),rva,is64,False)+self._imports(data,directories[13] if len(directories)>13 else (0,0),rva,is64,True)
        exports=self._exports(data,directories[0] if directories else (0,0),rva); resources=self._resources(data,directories[2] if len(directories)>2 else (0,0),rva); security=self._security(data,directories[4] if len(directories)>4 else (0,0),directories[9] if len(directories)>9 else (0,0),rva,is64)
        high=tuple(s.name for s in parsed if s.entropy>=7.2); api=tuple(sorted({fn for imp in imports for fn in imp.functions if fn in _SUSPICIOUS_APIS})); last=max((s.raw_size+self._rva(s.virtual_address,parsed) for s in parsed),default=0); overlay=max(0,len(data)-last); indicators=PeIndicators(bool(high and any(s.suspicious for s in parsed)),high,api,not bool(imports),overlay,False,tuple(x for x in ("debugger_api" if any("Debugger" in a or "NtQuery" in a for a in api) else "", "process_injection_api" if any(a in api for a in ("WriteProcessMemory","CreateRemoteThread")) else "") if x))
        return PeInfo("dll" if chars&0x2000 else "exe","MZ","PE\\0\\0",_MACHINES.get(machine,hex(machine)),entry,imagebase,_SUBSYSTEMS.get(subsystem,hex(subsystem)),chars,datetime.fromtimestamp(timestamp,tz=timezone.utc),sections,magic,tuple(parsed),imports,exports,resources,security,indicators)
    @staticmethod
    def _rva(value:int, sections:list[PeSection])->int:
        for s in sections:
            if s.virtual_address<=value<s.virtual_address+max(s.virtual_size,s.raw_size): return value-s.virtual_address+s.raw_offset
        return value
    @staticmethod
    def _entropy(blob:bytes)->float:
        if not blob:return 0.0
        counts=[blob.count(bytes([i])) for i in range(256)]; length=len(blob); return -sum((n/length)*math.log2(n/length) for n in counts if n)
    def _imports(self,data,directory,rva,is64,delayed):
        start,size=directory; pos=rva(start); result=[]; width=8 if is64 else 4; ordinal_mask=1 << (63 if is64 else 31)
        for _ in range(4096):
            if pos+20>len(data): break
            original,_,_,name_rva,first=struct.unpack_from("<IIIII",data,pos)
            if not any((original,name_rva,first)): break
            name_pos=rva(name_rva); library=self._cstring(data,name_pos); thunk=rva(original or first); functions=[]
            for _ in range(65536):
                if thunk+width>len(data): break
                value=struct.unpack_from("<Q" if is64 else "<I",data,thunk)[0]
                if not value: break
                functions.append("ordinal:"+str(value & 0xffff) if value&ordinal_mask else self._cstring(data,rva(value)+2)); thunk+=width
            result.append(PeImport(library,tuple(functions),delayed)); pos+=20
        return tuple(result)
    def _exports(self,data,directory,rva):
        start,_=directory; pos=rva(start)
        if not start or pos+40>len(data): return ()
        base,nfunc,nname,addr_funcs,addr_names,addr_ord=struct.unpack_from("<IIIIII",data,pos+16); names={}
        for i in range(nname):
            p=rva(addr_names)+i*4; q=rva(addr_ord)+i*2
            if p+4<=len(data) and q+2<=len(data): names[struct.unpack_from("<H",data,q)[0]]=self._cstring(data,rva(struct.unpack_from("<I",data,p)[0]))
        return tuple(PeExport(names.get(i),base+i,struct.unpack_from("<I",data,rva(addr_funcs)+i*4)[0]) for i in range(nfunc) if rva(addr_funcs)+i*4+4<=len(data))
    def _resources(self,data,directory,rva):
        start,_=directory; pos=rva(start)
        if not start or pos+16>len(data): return PeResourceInfo((),False,False,False)
        count=sum(struct.unpack_from("<HH",data,pos+12)); types=[]
        for i in range(count):
            p=pos+16+i*8
            if p+8>len(data): break
            ident=struct.unpack_from("<I",data,p)[0]; types.append(_RESOURCE_NAMES.get(ident,str(ident)))
        values=tuple(sorted(set(types))); return PeResourceInfo(values,"icon" in values or "group_icon" in values,"version" in values,"manifest" in values)
    @staticmethod
    def _cstring(data, pos):
        if pos >= len(data):
            return ""
        end = data.find(b"\x00", pos)
        if end < 0:
            end = len(data)
        return data[pos:end].decode("ascii", "replace")
    def _security(self,data,certificate,tls,rva,is64):
        offset,size=certificate; return PeSecurityInfo(bool(offset and size),offset or None,size or None,(),b"Rich" in data[:0x200])
