from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment

with open('elfs//0a1c2f23efa1ccc2558e140fa35e9b0d', 'rb') as elffile:
            # for segment in ELFFile(elffile).iter_segments():
            #     if segment.header.p_filesz != segment.header.p_memsz:
            #         seg_head = segment.header
            #         print(f"Type: {seg_head.p_type}\nOffset: {hex(seg_head.p_offset)}\nSize in file:{hex(seg_head.p_filesz)}\nSize in memory:{hex(seg_head.p_memsz)}")
    print(ELFFile(elffile))
    print(ELFFile(elffile).num_sections())
    print(ELFFile(elffile).num_segments())
    # for feature in ELFFile(elffile).iter_sections():
    #     print(feature)
    print(ELFFile(elffile).has_dwarf_info())
    print(ELFFile(elffile).get_dwarf_info())
    # print(ELFFile(elffile).get_dwarf_info().config)
    print(ELFFile(elffile).get_dwarf_info().config.machine_arch)
    print(ELFFile(elffile).get_dwarf_info().config.default_address_size)
    print(ELFFile(elffile).get_dwarf_info().config.little_endian)
    print(ELFFile(elffile).get_dwarf_info().debug_info_sec)
    print(ELFFile(elffile).get_dwarf_info().debug_aranges_sec)
    print(ELFFile(elffile).get_dwarf_info().debug_abbrev_sec)
    print(ELFFile(elffile).get_dwarf_info().debug_frame_sec)
    print(ELFFile(elffile).get_dwarf_info().eh_frame_sec)
    print(ELFFile(elffile).get_dwarf_info().debug_str_sec)
    print(ELFFile(elffile).get_dwarf_info().debug_loc_sec)
    print(ELFFile(elffile).get_dwarf_info().debug_ranges_sec)
    print(ELFFile(elffile).get_dwarf_info().debug_line_sec)
    print(ELFFile(elffile).get_dwarf_info().debug_pubtypes_sec)
    print(ELFFile(elffile).get_dwarf_info().debug_pubnames_sec)


    # for feature in ELFFile(elffile).iter_segments():
    #     print(feature)
    #     print(feature.header)
    #     print(feature.header.p_type)
    #     print(feature.header.p_offset)
    #     print(feature.header.p_filesz)
    #     print(feature.header.p_memsz)
    #     print(feature.header.p_flags)
    #     print(feature.header.p_align)
    #     print(feature.header.p_vaddr)
    #     print(feature.header.p_paddr)
    #     print()
