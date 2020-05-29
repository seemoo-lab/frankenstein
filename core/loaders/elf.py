import sys
import tempfile
from elftools.elf import elffile

class elfloader:
    """
        Handles ELF file import including coredump symbol recovery
    """

    def __init__(self, fname, offset=0x00):
        f = open(fname, "rb")
        self.elf = elffile.ELFFile(f)
        self.offset = offset

        self.reassembled = {}

    def iter_segments(self):
        """
            Iterates over all segments. Retuns {"vaddr": vaddr, "size": size, "data": data}
        """
        for segment in self.elf.iter_segments():
            if segment.header.p_type == 'PT_LOAD':
                vaddr = segment.header.p_vaddr + self.offset
                size = segment.header.p_memsz
                data = segment.data()
                yield {"vaddr": vaddr, "size": size, "data": data}

    def iter_symbols(self):
        """
            Iterates over all symbols in ELF or Core files
        """
        for section in self.elf.iter_sections():
            if section.header.sh_type in ['SHT_SYMTAB', 'SHT_DYNSYM']:
                for symbol in section.iter_symbols():
                    name = symbol.name
                    value = symbol.entry["st_value"] + self.offset
                    typ = symbol.entry["st_info"]["type"] # STT_NOTYPE STT_FUNC STT_FILE

                    if name != "" and "$" not in name:
                        yield {"name": name, "value": value, "type": typ}

            #  Find ELF files in core file
            if section.header.sh_type in ['SHT_NOTE']:
                for note in section.iter_notes():
                    if note.n_type == "NT_FILE":
                        print("Found NT_FILE")
                        for fname, desc in zip(note["n_desc"]["filename"],  note["n_desc"]["Elf_Nt_File_Entry"]):
                            if fname[:9] == b"/dev/zero":
                                continue
                            print(fname, desc)
                            #segment = self.get_segment(desc["vm_start"])
                            #data = segment.data()[:segment.header["p_filesz"]]
                            #self.reassemble_elf(fname, data,  desc["vm_start"])
                            if desc["page_offset"]:
                                try:
                                    e = elfloader(fname, desc["vm_start"])
                                    for x in e.iter_symbols():
                                        yield x
                                except:
                                    pass
                                    



        for x in self.iter_symbols_reassembled():
            yield x

    """
        Not working yet
    """
    def iter_symbols_reassembled(self):
        print(self.reassembled)
        for fname in self.reassembled.keys():
            (tmp, vaddr) = self.reassembled[fname]
            tmp.file.seek(0)
            print(fname)
            if tmp.file.read(4) == b"\x7fELF":
                print("Found ELF file %s" % fname)
                print(tmp.name)
                tmp.file.close()
                try:
                    e = elfloader(tmp.name, vaddr)
                    for x in e.iter_symbols():
                        yield x
                except:
                    print("fail")
                    import traceback; traceback.print_exc()
                input()

            
    """
        Not working yet
    """
    def reassemble_elf(self, fname, data, vaddr):
        """
            Reassembles ELF files from pages in core dump
        """
        if fname not in self.reassembled:
            tmp = tempfile.NamedTemporaryFile()
            tmp.file.write(data)
            self.reassembled[fname] = (tmp, vaddr)

        else:
            (tmp, vaddr) = self.reassembled[fname]
            tmp.file.write(data)
            self.reassembled[fname] = (tmp, vaddr)
            


    def get_segment(self, addr):
        """
            Get a segment data by address
        """
        for segment in self.elf.iter_segments():
            if segment.header.p_type == 'PT_LOAD':
                vaddr = segment.header.p_vaddr + self.offset
                if vaddr == addr:
                    #print(segment.header)
                    return segment


if __name__ == "__main__":
    e = elfloader(sys.argv[1])
    for x in e.iter_symbols():
        print(x)
