from distutils.command.clean import clean
import pandas as pd
import csv




features_list = ['file_name', 'file_size', 'num_sections', 'num_segments', 'has_dwarf_info', 'dwarf_info_config_machine_arch', 'dwarf_info_config_default_address_size', 'dwarf_info_config_little_endian', 'dwarf_info_debug_info_sec_name', 'dwarf_info_debug_info_sec_global_offset', 'dwarf_info_debug_info_sec_size', 'dwarf_info_debug_info_sec_address', 'dwarf_info_debug_aranges_sec_name', 'dwarf_info_debug_aranges_sec_global_offset', 'dwarf_info_debug_aranges_sec_size', 'dwarf_info_debug_aranges_sec_address', 'dwarf_info_debug_abbrev_sec_name', 'dwarf_info_debug_abbrev_sec_global_offset', 'dwarf_info_debug_abbrev_sec_size', 'dwarf_info_debug_abbrev_sec_address', 'dwarf_info_debug_frame_sec_name', 'dwarf_info_debug_frame_sec_global_offset', 'dwarf_info_debug_frame_sec_size', 'dwarf_info_debug_frame_sec_address', 'dwarf_info_debug_str_sec_name', 'dwarf_info_debug_str_sec_global_offset', 'dwarf_info_debug_str_sec_size', 'dwarf_info_debug_str_sec_address', 'dwarf_info_debug_loc_sec_name', 'dwarf_info_debug_loc_sec_global_offset', 'dwarf_info_debug_loc_sec_size', 'dwarf_info_debug_loc_sec_address', 'dwarf_info_debug_ranges_sec_name', 'dwarf_info_debug_ranges_sec_global_offset', 'dwarf_info_debug_ranges_sec_size', 'dwarf_info_debug_ranges_sec_address', 'dwarf_info_debug_line_sec_name', 'dwarf_info_debug_line_sec_global_offset', 'dwarf_info_debug_line_sec_size', 'dwarf_info_debug_line_sec_address', 'dwarf_info_debug_pubtypes_sec_name', 'dwarf_info_debug_pubtypes_sec_global_offset', 'dwarf_info_debug_pubtypes_sec_size', 'dwarf_info_debug_pubtypes_sec_address', 'dwarf_info_debug_pubnames_sec_name', 'dwarf_info_debug_pubnames_sec_global_offset', 'dwarf_info_debug_pubnames_sec_size', 'dwarf_info_debug_pubnames_sec_address', 'has_ehabi_info', 'ehabi_infos', 'machine_arch', 'shstrndx', 'sec_header_sh_name', 'sec_header_sh_type', 'sec_header_sh_flags', 'sec_header_sh_addr', 'sec_header_sh_offset', 'sec_header_sh_size', 'sec_header_sh_link', 'sec_header_sh_info', 'sec_header_sh_addralign', 'sec_header_sh_entsize', 'elf_head_ident_EI_CLASS', 'elf_head_ident_EI_DATA', 'elf_head_ident_EI_OSABI', 'elf_head_ident_EI_ABIVERSION', 'elf_head_e_type', 'elf_head_e_machine', 'elf_head_e_entry', 'elf_head_e_phoff', 'elf_head_e_shoff', 'elf_head_e_flags', 'elf_head_e_ehsize', 'elf_head_e_phentsize', 'elf_head_e_phnum', 'elf_head_e_shentsize', 'elf_head_e_shnum', 'elf_head_e_shstrndx', 'seg0_head_p_type', 'seg0_PT_LOAD_p_offset', 'seg0_PT_LOAD_p_filesz', 'seg0_PT_LOAD_p_memsz', 'seg0_PT_LOAD_p_flags', 'seg0_PT_LOAD_p_align', 'seg0_PT_LOAD_p_vaddr', 'seg0_PT_LOAD_p_paddr', 'seg1_head_p_type', 'seg1_PT_LOAD_p_offset', 'seg1_PT_LOAD_p_filesz', 'seg1_PT_LOAD_p_memsz', 'seg1_PT_LOAD_p_flags', 'seg1_PT_LOAD_p_align', 'seg1_PT_LOAD_p_vaddr', 'seg1_PT_LOAD_p_paddr', 'seg2_head_p_type', 'seg2_PT_GNU_STACK_p_offset', 'seg2_PT_GNU_STACK_p_filesz', 'seg2_PT_GNU_STACK_p_memsz', 'seg2_PT_GNU_STACK_p_flags', 'seg2_PT_GNU_STACK_p_align', 'seg2_PT_GNU_STACK_p_vaddr', 'seg2_PT_GNU_STACK_p_paddr', 'section__sh_name', 'section__sh_type', 'section__sh_flags', 'section__sh_addr', 'section__sh_offset', 'section__sh_size', 'section__sh_link', 'section__sh_info', 'section__sh_addralign', 'section__sh_entsize', 'section_init', 'section_init_sh_name', 'section_init_sh_type', 'section_init_sh_flags', 'section_init_sh_addr', 'section_init_sh_offset', 'section_init_sh_size', 'section_init_sh_link', 'section_init_sh_info', 'section_init_sh_addralign', 'section_init_sh_entsize', 'section_text', 'section_text_sh_name', 'section_text_sh_type', 'section_text_sh_flags', 'section_text_sh_addr', 'section_text_sh_offset', 'section_text_sh_size', 'section_text_sh_link', 'section_text_sh_info', 'section_text_sh_addralign', 'section_text_sh_entsize', 'section_fini', 'section_fini_sh_name', 'section_fini_sh_type', 'section_fini_sh_flags', 'section_fini_sh_addr', 'section_fini_sh_offset', 'section_fini_sh_size', 'section_fini_sh_link', 'section_fini_sh_info', 'section_fini_sh_addralign', 'section_fini_sh_entsize', 'section_rodata', 'section_rodata_sh_name', 'section_rodata_sh_type', 'section_rodata_sh_flags', 'section_rodata_sh_addr', 'section_rodata_sh_offset', 'section_rodata_sh_size', 'section_rodata_sh_link', 'section_rodata_sh_info', 'section_rodata_sh_addralign', 'section_rodata_sh_entsize', 'section_ctors', 'section_ctors_sh_name', 'section_ctors_sh_type', 'section_ctors_sh_flags', 'section_ctors_sh_addr', 'section_ctors_sh_offset', 'section_ctors_sh_size', 'section_ctors_sh_link', 'section_ctors_sh_info', 'section_ctors_sh_addralign', 'section_ctors_sh_entsize', 'section_dtors', 'section_dtors_sh_name', 'section_dtors_sh_type', 'section_dtors_sh_flags', 'section_dtors_sh_addr', 'section_dtors_sh_offset', 'section_dtors_sh_size', 'section_dtors_sh_link', 'section_dtors_sh_info', 'section_dtors_sh_addralign', 'section_dtors_sh_entsize', 'section_data', 'section_data_sh_name', 'section_data_sh_type', 'section_data_sh_flags', 'section_data_sh_addr', 'section_data_sh_offset', 'section_data_sh_size', 'section_data_sh_link', 'section_data_sh_info', 'section_data_sh_addralign', 'section_data_sh_entsize', 'section_bss', 'section_bss_sh_name', 'section_bss_sh_type', 'section_bss_sh_flags', 'section_bss_sh_addr', 'section_bss_sh_offset', 'section_bss_sh_size', 'section_bss_sh_link', 'section_bss_sh_info', 'section_bss_sh_addralign', 'section_bss_sh_entsize', 'section_shstrtab', 'section_shstrtab_sh_name', 'section_shstrtab_sh_type', 'section_shstrtab_sh_flags', 'section_shstrtab_sh_addr', 'section_shstrtab_sh_offset', 'section_shstrtab_sh_size', 'section_shstrtab_sh_link', 'section_shstrtab_sh_info', 'section_shstrtab_sh_addralign', 'section_shstrtab_sh_entsize']

# given_file = 'examine.csv'
# given_data = pd.read_csv(given_file)
# given_data_columns_list = []
# for i in given_data.columns.values:
#         given_data_columns_list.append(i)
# for feature in features_list:
#     if feature not in given_data_columns_list:
#         print("{} was not present, adding it to table with values 0...".format(feature))
#         given_data[feature] = ''
# for feature in given_data_columns_list:
#     if feature not in features_list:
#         print("{} was not present, removing it from table...".format(feature))
#         given_data = given_data.drop(feature, axis=1)

# given_data.to_csv('examine_modified.csv', index=False)


# with open('examine_modified.csv', 'r') as infile, open('examine_reordered.csv', 'a' ,newline='') as outfile:
#     fieldnames = features_list
#     writer = csv.DictWriter(outfile, fieldnames=fieldnames)
#     writer.writeheader()
#     for row in csv.DictReader(infile):
#         writer.writerow(row)

def get_unique_mappings(feature):
    tmplist = (sorted(clean_data[feature].unique().tolist()))
    tmpdict = {k: (v+1) for v, k in enumerate(tmplist)}
    return tmpdict


clean_data = pd.read_csv('examine_reordered.csv')

clean_data['has_dwarf_info'] = clean_data['has_dwarf_info'].replace({True: 1, False: 0})
clean_data['dwarf_info_config_machine_arch'] = clean_data['dwarf_info_config_machine_arch'].replace(get_unique_mappings('dwarf_info_config_machine_arch'))    
clean_data['dwarf_info_config_little_endian'] = clean_data['dwarf_info_config_little_endian'].replace({True: 1, False: 0})
clean_data['dwarf_info_debug_info_sec_name'] = clean_data['dwarf_info_debug_info_sec_name'].fillna(0)
clean_data['dwarf_info_debug_info_sec_global_offset'] = clean_data['dwarf_info_debug_info_sec_global_offset'].fillna(0)
clean_data['dwarf_info_debug_info_sec_size'] = clean_data['dwarf_info_debug_info_sec_size'].fillna(0)
clean_data['dwarf_info_debug_info_sec_address'] = clean_data['dwarf_info_debug_info_sec_address'].fillna(1)
clean_data['dwarf_info_debug_aranges_sec_name'] = clean_data['dwarf_info_debug_aranges_sec_name'].fillna(0)
clean_data['dwarf_info_debug_aranges_sec_global_offset'] = clean_data['dwarf_info_debug_aranges_sec_global_offset'].fillna(0)
clean_data['dwarf_info_debug_aranges_sec_size'] = clean_data['dwarf_info_debug_aranges_sec_size'].fillna(0)
clean_data['dwarf_info_debug_aranges_sec_address'] = clean_data['dwarf_info_debug_aranges_sec_address'].fillna(1)
clean_data['dwarf_info_debug_abbrev_sec_name'] = clean_data['dwarf_info_debug_abbrev_sec_name'].fillna(0)
clean_data['dwarf_info_debug_abbrev_sec_global_offset'] = clean_data['dwarf_info_debug_abbrev_sec_global_offset'].fillna(0)
clean_data['dwarf_info_debug_abbrev_sec_size'] = clean_data['dwarf_info_debug_abbrev_sec_size'].fillna(0)
clean_data['dwarf_info_debug_abbrev_sec_address'] = clean_data['dwarf_info_debug_abbrev_sec_address'].fillna(1)
clean_data['dwarf_info_debug_frame_sec_name'] = clean_data['dwarf_info_debug_frame_sec_name'].fillna(0)
clean_data['dwarf_info_debug_frame_sec_global_offset'] = clean_data['dwarf_info_debug_frame_sec_global_offset'].fillna(0)
clean_data['dwarf_info_debug_frame_sec_size'] = clean_data['dwarf_info_debug_frame_sec_size'].fillna(0)
clean_data['dwarf_info_debug_frame_sec_address'] = clean_data['dwarf_info_debug_frame_sec_address'].fillna(1)
clean_data['dwarf_info_debug_str_sec_name'] = clean_data['dwarf_info_debug_str_sec_name'].fillna(0)
clean_data['dwarf_info_debug_str_sec_global_offset'] = clean_data['dwarf_info_debug_str_sec_global_offset'].fillna(0)
clean_data['dwarf_info_debug_str_sec_size'] = clean_data['dwarf_info_debug_str_sec_size'].fillna(0)
clean_data['dwarf_info_debug_str_sec_address'] = clean_data['dwarf_info_debug_str_sec_address'].fillna(1)
clean_data['dwarf_info_debug_loc_sec_name'] = clean_data['dwarf_info_debug_loc_sec_name'].fillna(0)
clean_data['dwarf_info_debug_loc_sec_global_offset'] = clean_data['dwarf_info_debug_loc_sec_global_offset'].fillna(0)
clean_data['dwarf_info_debug_loc_sec_size'] = clean_data['dwarf_info_debug_loc_sec_size'].fillna(0)
clean_data['dwarf_info_debug_loc_sec_address'] = clean_data['dwarf_info_debug_loc_sec_address'].fillna(1)
clean_data['dwarf_info_debug_ranges_sec_name'] = clean_data['dwarf_info_debug_ranges_sec_name'].fillna(0)
clean_data['dwarf_info_debug_ranges_sec_global_offset'] = clean_data['dwarf_info_debug_ranges_sec_global_offset'].fillna(0)
clean_data['dwarf_info_debug_ranges_sec_size'] = clean_data['dwarf_info_debug_ranges_sec_size'].fillna(0)
clean_data['dwarf_info_debug_ranges_sec_address'] = clean_data['dwarf_info_debug_ranges_sec_address'].fillna(1)
clean_data['dwarf_info_debug_line_sec_name'] = clean_data['dwarf_info_debug_line_sec_name'].fillna(0)
clean_data['dwarf_info_debug_line_sec_global_offset'] = clean_data['dwarf_info_debug_line_sec_global_offset'].fillna(0)
clean_data['dwarf_info_debug_line_sec_size'] = clean_data['dwarf_info_debug_line_sec_size'].fillna(0)
clean_data['dwarf_info_debug_line_sec_address'] = clean_data['dwarf_info_debug_line_sec_address'].fillna(1)

# clean_data['dwarf_info_debug_pubtypes_sec_name'] = clean_data['dwarf_info_debug_pubtypes_sec_name'].fillna(0)
# clean_data['dwarf_info_debug_pubtypes_sec_global_offset'] = clean_data['dwarf_info_debug_pubtypes_sec_global_offset'].fillna(0)
# clean_data['dwarf_info_debug_pubtypes_sec_size'] = clean_data['dwarf_info_debug_pubtypes_sec_size'].fillna(0)
# clean_data['dwarf_info_debug_pubtypes_sec_address'] = clean_data['dwarf_info_debug_pubtypes_sec_address'].fillna(0)

clean_data['dwarf_info_debug_pubnames_sec_name'] = clean_data['dwarf_info_debug_pubnames_sec_name'].fillna(0)

clean_data['dwarf_info_debug_pubnames_sec_global_offset'] = clean_data['dwarf_info_debug_pubnames_sec_global_offset'].fillna(0)

clean_data['dwarf_info_debug_pubnames_sec_size'] = clean_data['dwarf_info_debug_pubnames_sec_size'].fillna(0)

clean_data['dwarf_info_debug_pubnames_sec_address'] = clean_data['dwarf_info_debug_pubnames_sec_address'].fillna(1)

clean_data['has_ehabi_info'] = clean_data['has_ehabi_info'].replace({True: 1, False: 0})

clean_data['ehabi_infos'] = clean_data['ehabi_infos'].fillna(0)

clean_data['machine_arch'] = clean_data['machine_arch'].replace(get_unique_mappings('machine_arch'))

clean_data['sec_header_sh_type'] = clean_data['sec_header_sh_type'].replace({'SHT_NULL': 0, 'SHT_STRTAB': 1})

clean_data['elf_head_ident_EI_CLASS'] = clean_data['elf_head_ident_EI_CLASS'].replace(get_unique_mappings('elf_head_ident_EI_CLASS'))
clean_data['elf_head_ident_EI_DATA'] = clean_data['elf_head_ident_EI_DATA'].replace(get_unique_mappings('elf_head_ident_EI_DATA'))
clean_data['elf_head_ident_EI_OSABI'] = clean_data['elf_head_ident_EI_OSABI'].replace(get_unique_mappings('elf_head_ident_EI_OSABI'))
clean_data['elf_head_e_type'] = clean_data['elf_head_e_type'].replace(get_unique_mappings('elf_head_e_type'))
clean_data['elf_head_e_machine'] = clean_data['elf_head_e_machine'].replace(get_unique_mappings('elf_head_e_machine'))
clean_data['seg0_head_p_type'] = clean_data['seg0_head_p_type'].replace(get_unique_mappings('seg0_head_p_type'))

clean_data['seg1_head_p_type'] = clean_data['seg1_head_p_type'].fillna(0)
# clean_data['seg1_head_p_type'] = clean_data['seg1_head_p_type'].replace(get_unique_mappings('seg1_head_p_type'))

clean_data['seg2_head_p_type'] = clean_data['seg2_head_p_type'].fillna(0)
# clean_data['seg2_head_p_type'] = clean_data['seg2_head_p_type'].replace(get_unique_mappings('seg1_head_p_type'))

clean_data['section__sh_name'] = clean_data['section__sh_name'].fillna(1)
clean_data['section__sh_type'] = clean_data['section__sh_type'].fillna(0)
clean_data['section__sh_flags'] = clean_data['section__sh_flags'].fillna(1)
clean_data['section__sh_addr'] = clean_data['section__sh_addr'].fillna(1)
clean_data['section__sh_offset'] = clean_data['section__sh_offset'].fillna(1)
clean_data['section__sh_size'] = clean_data['section__sh_size'].fillna(1)
clean_data['section__sh_link'] = clean_data['section__sh_link'].fillna(1)
clean_data['section__sh_info'] = clean_data['section__sh_info'].fillna(1)
clean_data['section__sh_addralign'] = clean_data['section__sh_addralign'].fillna(1)
clean_data['section__sh_entsize'] = clean_data['section__sh_entsize'].fillna(1)
clean_data['section_init'] = clean_data['section_init'].fillna(1)
clean_data['section_init_sh_name'] = clean_data['section_init_sh_name'].fillna(0)
clean_data['section_init_sh_type'] = clean_data['section_init_sh_type'].fillna(0)
clean_data['section_init_sh_flags'] = clean_data['section_init_sh_flags'].fillna(0)
clean_data['section_init_sh_addr'] = clean_data['section_init_sh_addr'].fillna(0)
clean_data['section_init_sh_offset'] = clean_data['section_init_sh_offset'].fillna(0)
clean_data['section_init_sh_size'] = clean_data['section_init_sh_size'].fillna(0)
clean_data['section_init_sh_link'] = clean_data['section_init_sh_link'].fillna(1)
clean_data['section_init_sh_info'] = clean_data['section_init_sh_info'].fillna(1)
clean_data['section_init_sh_addralign'] = clean_data['section_init_sh_addralign'].fillna(0)
clean_data['section_init_sh_entsize'] = clean_data['section_init_sh_entsize'].fillna(1)
clean_data['section_text'] = clean_data['section_text'].fillna(0)
clean_data['section_text_sh_name'] = clean_data['section_text_sh_name'].fillna(0)
clean_data['section_text_sh_type'] = clean_data['section_text_sh_type'].fillna(0)
clean_data['section_text_sh_flags'] = clean_data['section_text_sh_flags'].fillna(0)
clean_data['section_text_sh_addr'] = clean_data['section_text_sh_addr'].fillna(0)
clean_data['section_text_sh_offset'] = clean_data['section_text_sh_offset'].fillna(0)
clean_data['section_text_sh_size'] = clean_data['section_text_sh_size'].fillna(0)
clean_data['section_text_sh_link'] = clean_data['section_text_sh_link'].fillna(1)
clean_data['section_text_sh_info'] = clean_data['section_text_sh_info'].fillna(1)
clean_data['section_text_sh_addralign'] = clean_data['section_text_sh_addralign'].fillna(0)
clean_data['section_text_sh_entsize'] = clean_data['section_text_sh_entsize'].fillna(1)
clean_data['section_fini'] = clean_data['section_fini'].fillna(0)
clean_data['section_fini_sh_name'] = clean_data['section_fini_sh_name'].fillna(0)
clean_data['section_fini_sh_type'] = clean_data['section_fini_sh_type'].fillna(0)
clean_data['section_fini_sh_flags'] = clean_data['section_fini_sh_flags'].fillna(0)
clean_data['section_fini_sh_addr'] = clean_data['section_fini_sh_addr'].fillna(0)
clean_data['section_fini_sh_offset'] = clean_data['section_fini_sh_offset'].fillna(0)
clean_data['section_fini_sh_size'] = clean_data['section_fini_sh_size'].fillna(0)
clean_data['section_fini_sh_link'] = clean_data['section_fini_sh_link'].fillna(1)
clean_data['section_fini_sh_info'] = clean_data['section_fini_sh_info'].fillna(1)
clean_data['section_fini_sh_addralign'] = clean_data['section_fini_sh_addralign'].fillna(0)
clean_data['section_fini_sh_entsize'] = clean_data['section_fini_sh_entsize'].fillna(0)
clean_data['section_rodata'] = clean_data['section_rodata'].fillna(0)
clean_data['section_rodata_sh_name'] = clean_data['section_rodata_sh_name'].fillna(0)
clean_data['section_rodata_sh_type'] = clean_data['section_rodata_sh_type'].fillna(0)
clean_data['section_rodata_sh_flags'] = clean_data['section_rodata_sh_flags'].fillna(0)
clean_data['section_rodata_sh_addr'] = clean_data['section_rodata_sh_addr'].fillna(0)
clean_data['section_rodata_sh_offset'] = clean_data['section_rodata_sh_offset'].fillna(0)
clean_data['section_rodata_sh_size'] = clean_data['section_rodata_sh_size'].fillna(0)
clean_data['section_rodata_sh_link'] = clean_data['section_rodata_sh_link'].fillna(1)
clean_data['section_rodata_sh_info'] = clean_data['section_rodata_sh_info'].fillna(1)
clean_data['section_rodata_sh_addralign'] = clean_data['section_rodata_sh_addralign'].fillna(0)
clean_data['section_rodata_sh_entsize'] = clean_data['section_rodata_sh_entsize'].fillna(2)

clean_data['section_data'] = clean_data['section_data'].fillna(0)
clean_data['section_data_sh_name'] = clean_data['section_data_sh_name'].fillna(0)
clean_data['section_data_sh_type'] = clean_data['section_data_sh_type'].fillna(0)
clean_data['section_data_sh_flags'] = clean_data['section_data_sh_flags'].fillna(0)
clean_data['section_data_sh_addr'] = clean_data['section_data_sh_addr'].fillna(0)
clean_data['section_data_sh_offset'] = clean_data['section_data_sh_offset'].fillna(0)
clean_data['section_data_sh_size'] = clean_data['section_data_sh_size'].fillna(0)
clean_data['section_data_sh_link'] = clean_data['section_data_sh_link'].fillna(1)
clean_data['section_data_sh_info'] = clean_data['section_data_sh_info'].fillna(1)
clean_data['section_data_sh_addralign'] = clean_data['section_data_sh_addralign'].fillna(0)
clean_data['section_data_sh_entsize'] = clean_data['section_data_sh_entsize'].fillna(1)
clean_data['section_bss'] = clean_data['section_bss'].fillna(0)
clean_data['section_bss_sh_name'] = clean_data['section_bss_sh_name'].fillna(0)
clean_data['section_bss_sh_type'] = clean_data['section_bss_sh_type'].fillna(0)
clean_data['section_bss_sh_flags'] = clean_data['section_bss_sh_flags'].fillna(0)
clean_data['section_bss_sh_addr'] = clean_data['section_bss_sh_addr'].fillna(0)
clean_data['section_bss_sh_offset'] = clean_data['section_bss_sh_offset'].fillna(0)
clean_data['section_bss_sh_size'] = clean_data['section_bss_sh_size'].fillna(0)
clean_data['section_bss_sh_link'] = clean_data['section_bss_sh_link'].fillna(1)
clean_data['section_bss_sh_info'] = clean_data['section_bss_sh_info'].fillna(1)
clean_data['section_bss_sh_addralign'] = clean_data['section_bss_sh_addralign'].fillna(0)
clean_data['section_bss_sh_entsize'] = clean_data['section_bss_sh_entsize'].fillna(1)
clean_data['section_shstrtab'] = clean_data['section_shstrtab'].fillna(0)
clean_data['section_shstrtab_sh_name'] = clean_data['section_shstrtab_sh_name'].fillna(0)
clean_data['section_shstrtab_sh_type'] = clean_data['section_shstrtab_sh_type'].fillna(0)
clean_data['section_shstrtab_sh_flags'] = clean_data['section_shstrtab_sh_flags'].fillna(1)
clean_data['section_shstrtab_sh_addr'] = clean_data['section_shstrtab_sh_addr'].fillna(1)
clean_data['section_shstrtab_sh_offset'] = clean_data['section_shstrtab_sh_offset'].fillna(0)
clean_data['section_shstrtab_sh_size'] = clean_data['section_shstrtab_sh_size'].fillna(0)
clean_data['section_shstrtab_sh_link'] = clean_data['section_shstrtab_sh_link'].fillna(1)
clean_data['section_shstrtab_sh_info'] = clean_data['section_shstrtab_sh_info'].fillna(1)
clean_data['section_shstrtab_sh_addralign'] = clean_data['section_shstrtab_sh_addralign'].fillna(0)
clean_data['section_shstrtab_sh_entsize'] = clean_data['section_shstrtab_sh_entsize'].fillna(1)








clean_data.to_csv('examine_reordered_perfect.csv', index=False)