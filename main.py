import csv
import sys
import os
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment

def get_elf_info(elf):
        
    with open(elf, 'rb') as elffile:
        features_dict = {}

        features_dict['file_name'] = os.path.basename(elffile.name)
        features_dict['file_size'] = os.path.getsize(elffile.name)

        elffile = ELFFile(elffile)
        
        num_sections = elffile.num_sections()
        num_segments = elffile.num_segments()
        has_dwarf_info = elffile.has_dwarf_info()
        dwarf_info_config_machine_arch = (elffile.get_dwarf_info().config.machine_arch)
        dwarf_info_config_default_address_size = (elffile.get_dwarf_info().config.default_address_size)
        dwarf_info_config_little_endian = (elffile.get_dwarf_info().config.little_endian)
        dwarf_info_debug_info_sec = (elffile.get_dwarf_info().debug_info_sec)
        dwarf_info_debug_aranges_sec = (elffile.get_dwarf_info().debug_aranges_sec)
        dwarf_info_debug_abbrev_sec = (elffile.get_dwarf_info().debug_abbrev_sec)
        dwarf_info_debug_frame_sec = (elffile.get_dwarf_info().debug_frame_sec)
        dwarf_info_eh_frame_sec = (elffile.get_dwarf_info().eh_frame_sec)
        dwarf_info_debug_str_sec = (elffile.get_dwarf_info().debug_str_sec)
        dwarf_info_debug_loc_sec = (elffile.get_dwarf_info().debug_loc_sec)
        dwarf_info_debug_ranges_sec = (elffile.get_dwarf_info().debug_ranges_sec)
        dwarf_info_debug_line_sec = (elffile.get_dwarf_info().debug_line_sec)
        dwarf_info_debug_pubtypes_sec = (elffile.get_dwarf_info().debug_pubtypes_sec)
        dwarf_info_debug_pubnames_sec = (elffile.get_dwarf_info().debug_pubnames_sec)
        has_ehabi_info = (elffile.has_ehabi_info())
        ehabi_infos = (elffile.get_ehabi_infos())
        machine_arch = (elffile.get_machine_arch())
        shstrndx = (elffile.get_shstrndx())
        identify_file = (elffile._identify_file())
        sec_header_sh_name = (elffile._get_section_header_stringtable().header.sh_name)
        sec_header_sh_type = (elffile._get_section_header_stringtable().header.sh_type)
        sec_header_sh_flags = (elffile._get_section_header_stringtable().header.sh_flags)
        sec_header_sh_addr = (elffile._get_section_header_stringtable().header.sh_addr)
        sec_header_sh_offset = (elffile._get_section_header_stringtable().header.sh_offset)
        sec_header_sh_size = (elffile._get_section_header_stringtable().header.sh_size)
        sec_header_sh_link = (elffile._get_section_header_stringtable().header.sh_link)
        sec_header_sh_info = (elffile._get_section_header_stringtable().header.sh_info)
        sec_header_sh_addralign = (elffile._get_section_header_stringtable().header.sh_addralign)
        sec_header_sh_entsize = (elffile._get_section_header_stringtable().header.sh_entsize)
        elf_head_ident_EI_MAG = (elffile._parse_elf_header().e_ident.EI_MAG)
        elf_head_ident_EI_CLASS = (elffile._parse_elf_header().e_ident.EI_CLASS)
        elf_head_ident_EI_DATA = (elffile._parse_elf_header().e_ident.EI_DATA)
        elf_head_ident_EI_VERSION = (elffile._parse_elf_header().e_ident.EI_VERSION)
        elf_head_ident_EI_OSABI = (elffile._parse_elf_header().e_ident.EI_OSABI)
        elf_head_ident_EI_ABIVERSION = (elffile._parse_elf_header().e_ident.EI_ABIVERSION)
        elf_head_e_type = (elffile._parse_elf_header().e_type)
        elf_head_e_machine= (elffile._parse_elf_header().e_machine)
        elf_head_e_version = (elffile._parse_elf_header().e_version)
        elf_head_e_entry = (elffile._parse_elf_header().e_entry)
        elf_head_e_phoff = (elffile._parse_elf_header().e_phoff)
        elf_head_e_shoff = (elffile._parse_elf_header().e_shoff)
        elf_head_e_flags = (elffile._parse_elf_header().e_flags)
        elf_head_e_ehsize = (elffile._parse_elf_header().e_ehsize)
        elf_head_e_phentsize = (elffile._parse_elf_header().e_phentsize)
        elf_head_e_phnum = (elffile._parse_elf_header().e_phnum)
        elf_head_e_shentsize = (elffile._parse_elf_header().e_shentsize)
        elf_head_e_shnum = (elffile._parse_elf_header().e_shnum)
        elf_head_e_shstrndx = (elffile._parse_elf_header().e_shstrndx)

        features_dict['num_sections'] = num_sections
        features_dict['num_segments'] = num_segments
        features_dict['has_dwarf_info'] = has_dwarf_info
        features_dict['dwarf_info_config_machine_arch'] = dwarf_info_config_machine_arch
        features_dict['dwarf_info_config_default_address_size'] = dwarf_info_config_default_address_size
        features_dict['dwarf_info_config_little_endian'] = dwarf_info_config_little_endian
        features_dict['dwarf_info_debug_info_sec'] = dwarf_info_debug_info_sec
        features_dict['dwarf_info_debug_aranges_sec'] = dwarf_info_debug_aranges_sec
        features_dict['dwarf_info_debug_abbrev_sec'] = dwarf_info_debug_abbrev_sec
        features_dict['dwarf_info_debug_frame_sec'] = dwarf_info_debug_frame_sec
        features_dict['dwarf_info_eh_frame_sec'] = dwarf_info_eh_frame_sec
        features_dict['dwarf_info_debug_str_sec'] = dwarf_info_debug_str_sec
        features_dict['dwarf_info_debug_loc_sec'] = dwarf_info_debug_loc_sec
        features_dict['dwarf_info_debug_ranges_sec'] = dwarf_info_debug_ranges_sec
        features_dict['dwarf_info_debug_line_sec'] = dwarf_info_debug_line_sec
        features_dict['dwarf_info_debug_pubtypes_sec'] = dwarf_info_debug_pubtypes_sec
        features_dict['dwarf_info_debug_pubnames_sec'] = dwarf_info_debug_pubnames_sec
        features_dict['has_ehabi_info'] = has_ehabi_info
        features_dict['ehabi_infos'] = ehabi_infos
        features_dict['machine_arch'] = machine_arch
        features_dict['shstrndx'] = shstrndx
        features_dict['identify_file'] = identify_file
        features_dict['sec_header_sh_name'] = sec_header_sh_name
        features_dict['sec_header_sh_type'] = sec_header_sh_type
        features_dict['sec_header_sh_flags'] = sec_header_sh_flags
        features_dict['sec_header_sh_addr'] = sec_header_sh_addr
        features_dict['sec_header_sh_offset'] = sec_header_sh_offset
        features_dict['sec_header_sh_size'] = sec_header_sh_size
        features_dict['sec_header_sh_link'] = sec_header_sh_link
        features_dict['sec_header_sh_info'] = sec_header_sh_info
        features_dict['sec_header_sh_addralign'] = sec_header_sh_addralign
        features_dict['sec_header_sh_entsize'] = sec_header_sh_entsize
        features_dict['elf_head_ident_EI_MAG'] = elf_head_ident_EI_MAG
        features_dict['elf_head_ident_EI_CLASS'] = elf_head_ident_EI_CLASS
        features_dict['elf_head_ident_EI_DATA'] = elf_head_ident_EI_DATA
        features_dict['elf_head_ident_EI_VERSION'] = elf_head_ident_EI_VERSION
        features_dict['elf_head_ident_EI_OSABI'] = elf_head_ident_EI_OSABI
        features_dict['elf_head_ident_EI_ABIVERSION'] = elf_head_ident_EI_ABIVERSION
        features_dict['elf_head_e_type'] = elf_head_e_type
        features_dict['elf_head_e_machine'] = elf_head_e_machine
        features_dict['elf_head_e_version'] = elf_head_e_version
        features_dict['elf_head_e_entry'] = elf_head_e_entry
        features_dict['elf_head_e_phoff'] = elf_head_e_phoff
        features_dict['elf_head_e_shoff'] = elf_head_e_shoff
        features_dict['elf_head_e_flags'] = elf_head_e_flags
        features_dict['elf_head_e_ehsize'] = elf_head_e_ehsize
        features_dict['elf_head_e_phentsize'] = elf_head_e_phentsize
        features_dict['elf_head_e_phnum'] = elf_head_e_phnum
        features_dict['elf_head_e_shentsize'] = elf_head_e_shentsize
        features_dict['elf_head_e_shnum'] = elf_head_e_shnum
        features_dict['elf_head_e_shstrndx'] = elf_head_e_shstrndx


        temp = 0
        for segment in elffile.iter_segments():
            seg_head_p_type = (segment.header.p_type)
            features_dict[f'seg{temp}_head_p_type'] = segment.header.p_type
            seg_head_p_offset = (segment.header.p_offset)
            seg_head_p_filesz= (segment.header.p_filesz)
            seg_head_p_memsz = (segment.header.p_memsz)
            seg_head_p_flags = (segment.header.p_flags)
            seg_head_p_align = (segment.header.p_align)
            seg_head_p_vaddr = (segment.header.p_vaddr)
            seg_head_p_paddr = (segment.header.p_paddr)

            features_dict[f'seg{temp}_{seg_head_p_type}_p_offset'] = seg_head_p_offset
            features_dict[f'seg{temp}_{seg_head_p_type}_p_filesz'] = seg_head_p_filesz
            features_dict[f'seg{temp}_{seg_head_p_type}_p_memsz'] = seg_head_p_memsz
            features_dict[f'seg{temp}_{seg_head_p_type}_p_flags'] = seg_head_p_flags
            features_dict[f'seg{temp}_{seg_head_p_type}_p_align'] = seg_head_p_align
            features_dict[f'seg{temp}_{seg_head_p_type}_p_vaddr'] = seg_head_p_vaddr
            features_dict[f'seg{temp}_{seg_head_p_type}_p_paddr'] = seg_head_p_paddr
            temp += 1

        for section in elffile.iter_sections():
            section_name = (section.name)[1:]
            features_dict[f'section_{section_name}'] = section.name
            sechead_sh_name = (section.header.sh_name)
            sechead_sh_type = (section.header.sh_type)
            sechead_sh_flags = (section.header.sh_flags)
            sechead_sh_addr = (section.header.sh_addr)
            sechead_sh_offset = (section.header.sh_offset)
            sechead_sh_size = (section.header.sh_size)
            sechead_sh_link = (section.header.sh_link)
            sechead_sh_info = (section.header.sh_info)
            sechead_sh_addralign = (section.header.sh_addralign)
            sechead_sh_entsize = (section.header.sh_entsize)

            features_dict[f'section_{section_name}_sh_name'] = sechead_sh_name
            features_dict[f'section_{section_name}_sh_type'] = sechead_sh_type
            features_dict[f'section_{section_name}_sh_flags'] = sechead_sh_flags
            features_dict[f'section_{section_name}_sh_addr'] = sechead_sh_addr
            features_dict[f'section_{section_name}_sh_offset'] = sechead_sh_offset
            features_dict[f'section_{section_name}_sh_size'] = sechead_sh_size
            features_dict[f'section_{section_name}_sh_link'] = sechead_sh_link
            features_dict[f'section_{section_name}_sh_info'] = sechead_sh_info
            features_dict[f'section_{section_name}_sh_addralign'] = sechead_sh_addralign
            features_dict[f'section_{section_name}_sh_entsize'] = sechead_sh_entsize
    return features_dict

def formatdict(d, tab=0):
    s = ['{\n']
    for k,v in d.items():
        if isinstance(v, dict):
            v = format(v, tab+1)
        else:
            v = repr(v)

        s.append('%s%r: %s,\n' % ('  '*tab, k, v))
    s.append('%s}' % ('  '*tab))
    return ''.join(s)

def dict_to_txt(d, name):
    with open(name, "a") as text_file:
        print(formatdict(d), file=text_file)

def dict_to_csv(d, name):
    with open(name, 'a') as csv_file:
        w = csv.DictWriter(csv_file, d.keys())
        w.writeheader()
        # w.writerow(d)

try:
    if(os.path.isdir(sys.argv[1])):
        for filename in os.listdir(sys.argv[1]):
            info_dictionary = get_elf_info(sys.argv[1]+"/"+filename)
            # dict_to_txt(info_dictionary, 'dump.txt')
            dict_to_csv(info_dictionary, 'dump.csv')
    else:
        info_dictionary = get_elf_info(sys.argv[1])
        dict_to_txt(info_dictionary, 'dump.txt')
        dict_to_csv(info_dictionary, 'dump.csv')

except FileNotFoundError:
    print("specified file was not found")

