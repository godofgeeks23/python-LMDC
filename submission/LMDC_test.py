import csv
import sys
import os
import pandas as pd
import numpy as np
from distutils.log import info
import matplotlib.pyplot as plt
import pickle
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
import missingno as msno
from distutils.command.clean import clean
from unittest import result
from fileinput import filename
from tkinter.tix import Y_REGION
from matplotlib.transforms import Bbox
from sklearn.ensemble import ExtraTreesClassifier
from sklearn import preprocessing
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_fscore_support as score

# FEATURE EXTRACTION
# function to extract all avaialble features from the ELF file
def get_elf_info(elf):
    print("reading file - " + elf)    
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
        if dwarf_info_debug_info_sec is not None:
            dwarf_info_debug_info_sec_name = (elffile.get_dwarf_info().debug_info_sec.name)
            dwarf_info_debug_info_sec_global_offset = (elffile.get_dwarf_info().debug_info_sec.global_offset)
            dwarf_info_debug_info_sec_size = (elffile.get_dwarf_info().debug_info_sec.size)
            dwarf_info_debug_info_sec_address = (elffile.get_dwarf_info().debug_info_sec.address)
        else:
            dwarf_info_debug_info_sec_name = None
            dwarf_info_debug_info_sec_global_offset = None
            dwarf_info_debug_info_sec_size = None
            dwarf_info_debug_info_sec_address = None
        dwarf_info_debug_aranges_sec = (elffile.get_dwarf_info().debug_aranges_sec)
        if dwarf_info_debug_aranges_sec is not None:
            dwarf_info_debug_aranges_sec_name = (elffile.get_dwarf_info().debug_aranges_sec.name)
            dwarf_info_debug_aranges_sec_global_offset = (elffile.get_dwarf_info().debug_aranges_sec.global_offset)
            dwarf_info_debug_aranges_sec_size = (elffile.get_dwarf_info().debug_aranges_sec.size)
            dwarf_info_debug_aranges_sec_address = (elffile.get_dwarf_info().debug_aranges_sec.address)
        else:
            dwarf_info_debug_aranges_sec_name = None
            dwarf_info_debug_aranges_sec_global_offset = None
            dwarf_info_debug_aranges_sec_size = None
            dwarf_info_debug_aranges_sec_address = None
        dwarf_info_debug_abbrev_sec = (elffile.get_dwarf_info().debug_abbrev_sec)
        if dwarf_info_debug_abbrev_sec is not None:
            dwarf_info_debug_abbrev_sec_name = (elffile.get_dwarf_info().debug_abbrev_sec.name)
            dwarf_info_debug_abbrev_sec_global_offset = (elffile.get_dwarf_info().debug_abbrev_sec.global_offset)
            dwarf_info_debug_abbrev_sec_size = (elffile.get_dwarf_info().debug_abbrev_sec.size)
            dwarf_info_debug_abbrev_sec_address = (elffile.get_dwarf_info().debug_abbrev_sec.address)
        else:
            dwarf_info_debug_abbrev_sec_name = None
            dwarf_info_debug_abbrev_sec_global_offset = None
            dwarf_info_debug_abbrev_sec_size = None
            dwarf_info_debug_abbrev_sec_address = None
        dwarf_info_debug_frame_sec = (elffile.get_dwarf_info().debug_frame_sec)
        if dwarf_info_debug_frame_sec is not None:
            dwarf_info_debug_frame_sec_name = (elffile.get_dwarf_info().debug_frame_sec.name)
            dwarf_info_debug_frame_sec_global_offset = (elffile.get_dwarf_info().debug_frame_sec.global_offset)
            dwarf_info_debug_frame_sec_size = (elffile.get_dwarf_info().debug_frame_sec.size)
            dwarf_info_debug_frame_sec_address = (elffile.get_dwarf_info().debug_frame_sec.address)
        else:
            dwarf_info_debug_frame_sec_name = None
            dwarf_info_debug_frame_sec_global_offset = None
            dwarf_info_debug_frame_sec_size = None
            dwarf_info_debug_frame_sec_address = None
        dwarf_info_debug_str_sec = (elffile.get_dwarf_info().debug_str_sec)
        if dwarf_info_debug_str_sec is not None:
            dwarf_info_debug_str_sec_name = (elffile.get_dwarf_info().debug_str_sec.name)
            dwarf_info_debug_str_sec_global_offset = (elffile.get_dwarf_info().debug_str_sec.global_offset)
            dwarf_info_debug_str_sec_size = (elffile.get_dwarf_info().debug_str_sec.size)
            dwarf_info_debug_str_sec_address = (elffile.get_dwarf_info().debug_str_sec.address)
        else:
            dwarf_info_debug_str_sec_name = None
            dwarf_info_debug_str_sec_global_offset = None
            dwarf_info_debug_str_sec_size = None
            dwarf_info_debug_str_sec_address = None
        dwarf_info_debug_loc_sec = (elffile.get_dwarf_info().debug_loc_sec)
        if dwarf_info_debug_loc_sec is not None:
            dwarf_info_debug_loc_sec_name = (elffile.get_dwarf_info().debug_loc_sec.name)
            dwarf_info_debug_loc_sec_global_offset = (elffile.get_dwarf_info().debug_loc_sec.global_offset)
            dwarf_info_debug_loc_sec_size = (elffile.get_dwarf_info().debug_loc_sec.size)
            dwarf_info_debug_loc_sec_address = (elffile.get_dwarf_info().debug_loc_sec.address)
        else:
            dwarf_info_debug_loc_sec_name = None
            dwarf_info_debug_loc_sec_global_offset = None
            dwarf_info_debug_loc_sec_size = None
            dwarf_info_debug_loc_sec_address = None
        dwarf_info_debug_ranges_sec = (elffile.get_dwarf_info().debug_ranges_sec)
        if dwarf_info_debug_ranges_sec is not None:
            dwarf_info_debug_ranges_sec_name = (elffile.get_dwarf_info().debug_ranges_sec.name)
            dwarf_info_debug_ranges_sec_global_offset = (elffile.get_dwarf_info().debug_ranges_sec.global_offset)
            dwarf_info_debug_ranges_sec_size = (elffile.get_dwarf_info().debug_ranges_sec.size)
            dwarf_info_debug_ranges_sec_address = (elffile.get_dwarf_info().debug_ranges_sec.address)
        else:
            dwarf_info_debug_ranges_sec_name = None
            dwarf_info_debug_ranges_sec_global_offset = None
            dwarf_info_debug_ranges_sec_size = None
            dwarf_info_debug_ranges_sec_address = None
        dwarf_info_debug_line_sec = (elffile.get_dwarf_info().debug_line_sec)
        if dwarf_info_debug_line_sec is not None:
            dwarf_info_debug_line_sec_name = (elffile.get_dwarf_info().debug_line_sec.name)
            dwarf_info_debug_line_sec_global_offset = (elffile.get_dwarf_info().debug_line_sec.global_offset)
            dwarf_info_debug_line_sec_size = (elffile.get_dwarf_info().debug_line_sec.size)
            dwarf_info_debug_line_sec_address = (elffile.get_dwarf_info().debug_line_sec.address)
        else:
            dwarf_info_debug_line_sec_name = None
            dwarf_info_debug_line_sec_global_offset = None
            dwarf_info_debug_line_sec_size = None
            dwarf_info_debug_line_sec_address = None
        dwarf_info_debug_pubtypes_sec = (elffile.get_dwarf_info().debug_pubtypes_sec)
        if dwarf_info_debug_pubtypes_sec is not None:
            dwarf_info_debug_pubtypes_sec_name = (elffile.get_dwarf_info().debug_pubtypes_sec.name)
            dwarf_info_debug_pubtypes_sec_global_offset = (elffile.get_dwarf_info().debug_pubtypes_sec.global_offset)
            dwarf_info_debug_pubtypes_sec_size = (elffile.get_dwarf_info().debug_pubtypes_sec.size)
            dwarf_info_debug_pubtypes_sec_address = (elffile.get_dwarf_info().debug_pubtypes_sec.address)
        else:
            dwarf_info_debug_pubtypes_sec_name = None
            dwarf_info_debug_pubtypes_sec_global_offset = None
            dwarf_info_debug_pubtypes_sec_size = None
            dwarf_info_debug_pubtypes_sec_address = None
        dwarf_info_debug_pubnames_sec = (elffile.get_dwarf_info().debug_pubnames_sec)
        if dwarf_info_debug_pubnames_sec is not None:
            dwarf_info_debug_pubnames_sec_name = (elffile.get_dwarf_info().debug_pubnames_sec.name)
            dwarf_info_debug_pubnames_sec_global_offset = (elffile.get_dwarf_info().debug_pubnames_sec.global_offset)
            dwarf_info_debug_pubnames_sec_size = (elffile.get_dwarf_info().debug_pubnames_sec.size)
            dwarf_info_debug_pubnames_sec_address = (elffile.get_dwarf_info().debug_pubnames_sec.address)
        else:
            dwarf_info_debug_pubnames_sec_name = None
            dwarf_info_debug_pubnames_sec_global_offset = None
            dwarf_info_debug_pubnames_sec_size = None
            dwarf_info_debug_pubnames_sec_address = None
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
        features_dict['dwarf_info_debug_info_sec_name'] = dwarf_info_debug_info_sec_name
        features_dict['dwarf_info_debug_info_sec_global_offset'] = dwarf_info_debug_info_sec_global_offset
        features_dict['dwarf_info_debug_info_sec_size'] = dwarf_info_debug_info_sec_size
        features_dict['dwarf_info_debug_info_sec_address'] = dwarf_info_debug_info_sec_address
        features_dict['dwarf_info_debug_aranges_sec_name'] = dwarf_info_debug_aranges_sec_name
        features_dict['dwarf_info_debug_aranges_sec_global_offset'] = dwarf_info_debug_aranges_sec_global_offset
        features_dict['dwarf_info_debug_aranges_sec_size'] = dwarf_info_debug_aranges_sec_size
        features_dict['dwarf_info_debug_aranges_sec_address'] = dwarf_info_debug_aranges_sec_address
        features_dict['dwarf_info_debug_abbrev_sec_name'] = dwarf_info_debug_abbrev_sec_name
        features_dict['dwarf_info_debug_abbrev_sec_global_offset'] = dwarf_info_debug_abbrev_sec_global_offset
        features_dict['dwarf_info_debug_abbrev_sec_size'] = dwarf_info_debug_abbrev_sec_size
        features_dict['dwarf_info_debug_abbrev_sec_address'] = dwarf_info_debug_abbrev_sec_address
        features_dict['dwarf_info_debug_frame_sec_name'] = dwarf_info_debug_frame_sec_name
        features_dict['dwarf_info_debug_frame_sec_global_offset'] = dwarf_info_debug_frame_sec_global_offset
        features_dict['dwarf_info_debug_frame_sec_size'] = dwarf_info_debug_frame_sec_size
        features_dict['dwarf_info_debug_frame_sec_address'] = dwarf_info_debug_frame_sec_address
        features_dict['dwarf_info_debug_str_sec_name'] = dwarf_info_debug_str_sec_name
        features_dict['dwarf_info_debug_str_sec_global_offset'] = dwarf_info_debug_str_sec_global_offset
        features_dict['dwarf_info_debug_str_sec_size'] = dwarf_info_debug_str_sec_size
        features_dict['dwarf_info_debug_str_sec_address'] = dwarf_info_debug_str_sec_address
        features_dict['dwarf_info_debug_loc_sec_name'] = dwarf_info_debug_loc_sec_name
        features_dict['dwarf_info_debug_loc_sec_global_offset'] = dwarf_info_debug_loc_sec_global_offset
        features_dict['dwarf_info_debug_loc_sec_size'] = dwarf_info_debug_loc_sec_size
        features_dict['dwarf_info_debug_loc_sec_address'] = dwarf_info_debug_loc_sec_address
        features_dict['dwarf_info_debug_ranges_sec_name'] = dwarf_info_debug_ranges_sec_name
        features_dict['dwarf_info_debug_ranges_sec_global_offset'] = dwarf_info_debug_ranges_sec_global_offset
        features_dict['dwarf_info_debug_ranges_sec_size'] = dwarf_info_debug_ranges_sec_size
        features_dict['dwarf_info_debug_ranges_sec_address'] = dwarf_info_debug_ranges_sec_address
        features_dict['dwarf_info_debug_line_sec_name'] = dwarf_info_debug_line_sec_name
        features_dict['dwarf_info_debug_line_sec_global_offset'] = dwarf_info_debug_line_sec_global_offset
        features_dict['dwarf_info_debug_line_sec_size'] = dwarf_info_debug_line_sec_size
        features_dict['dwarf_info_debug_line_sec_address'] = dwarf_info_debug_line_sec_address
        features_dict['dwarf_info_debug_pubtypes_sec_name'] = dwarf_info_debug_pubtypes_sec_name
        features_dict['dwarf_info_debug_pubtypes_sec_global_offset'] = dwarf_info_debug_pubtypes_sec_global_offset
        features_dict['dwarf_info_debug_pubtypes_sec_size'] = dwarf_info_debug_pubtypes_sec_size
        features_dict['dwarf_info_debug_pubtypes_sec_address'] = dwarf_info_debug_pubtypes_sec_address
        features_dict['dwarf_info_debug_pubnames_sec_name'] = dwarf_info_debug_pubnames_sec_name
        features_dict['dwarf_info_debug_pubnames_sec_global_offset'] = dwarf_info_debug_pubnames_sec_global_offset
        features_dict['dwarf_info_debug_pubnames_sec_size'] = dwarf_info_debug_pubnames_sec_size
        features_dict['dwarf_info_debug_pubnames_sec_address'] = dwarf_info_debug_pubnames_sec_address
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

# utility function to save the dictionary to a CSV file
def dict_to_csv(d, name):
    keys = d[0].keys()
    with open(name, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, keys, extrasaction='ignore')
        dict_writer.writeheader()
        dict_writer.writerows(d)

# utility function to clean the dataset by generating unique numeric value for the string values in the dataset
def get_unique_mappings(feature):
    clean_data = pd.read_csv('examine_reordered.csv')
    tmplist = (sorted(clean_data[feature].unique().tolist()))
    tmpdict = {k: (v+1) for v, k in enumerate(tmplist)}
    return tmpdict

# DATA CLENAING
# function to clean the dataset for further processing
def clean_dataset():
    # these are the selected features which we obtained from the dataset during the training phase
    features_list = ['file_name', 'file_size', 'num_sections', 'num_segments', 'has_dwarf_info', 'dwarf_info_config_machine_arch', 'dwarf_info_config_default_address_size', 'dwarf_info_config_little_endian', 'dwarf_info_debug_info_sec_name', 'dwarf_info_debug_info_sec_global_offset', 'dwarf_info_debug_info_sec_size', 'dwarf_info_debug_info_sec_address', 'dwarf_info_debug_aranges_sec_name', 'dwarf_info_debug_aranges_sec_global_offset', 'dwarf_info_debug_aranges_sec_size', 'dwarf_info_debug_aranges_sec_address', 'dwarf_info_debug_abbrev_sec_name', 'dwarf_info_debug_abbrev_sec_global_offset', 'dwarf_info_debug_abbrev_sec_size', 'dwarf_info_debug_abbrev_sec_address', 'dwarf_info_debug_frame_sec_name', 'dwarf_info_debug_frame_sec_global_offset', 'dwarf_info_debug_frame_sec_size', 'dwarf_info_debug_frame_sec_address', 'dwarf_info_debug_str_sec_name', 'dwarf_info_debug_str_sec_global_offset', 'dwarf_info_debug_str_sec_size', 'dwarf_info_debug_str_sec_address', 'dwarf_info_debug_loc_sec_name', 'dwarf_info_debug_loc_sec_global_offset', 'dwarf_info_debug_loc_sec_size', 'dwarf_info_debug_loc_sec_address', 'dwarf_info_debug_ranges_sec_name', 'dwarf_info_debug_ranges_sec_global_offset', 'dwarf_info_debug_ranges_sec_size', 'dwarf_info_debug_ranges_sec_address', 'dwarf_info_debug_line_sec_name', 'dwarf_info_debug_line_sec_global_offset', 'dwarf_info_debug_line_sec_size', 'dwarf_info_debug_line_sec_address', 'dwarf_info_debug_pubtypes_sec_name', 'dwarf_info_debug_pubtypes_sec_global_offset', 'dwarf_info_debug_pubtypes_sec_size', 'dwarf_info_debug_pubtypes_sec_address', 'dwarf_info_debug_pubnames_sec_name', 'dwarf_info_debug_pubnames_sec_global_offset', 'dwarf_info_debug_pubnames_sec_size', 'dwarf_info_debug_pubnames_sec_address', 'has_ehabi_info', 'ehabi_infos', 'machine_arch', 'shstrndx', 'sec_header_sh_name', 'sec_header_sh_type', 'sec_header_sh_flags', 'sec_header_sh_addr', 'sec_header_sh_offset', 'sec_header_sh_size', 'sec_header_sh_link', 'sec_header_sh_info', 'sec_header_sh_addralign', 'sec_header_sh_entsize', 'elf_head_ident_EI_CLASS', 'elf_head_ident_EI_DATA', 'elf_head_ident_EI_OSABI', 'elf_head_ident_EI_ABIVERSION', 'elf_head_e_type', 'elf_head_e_machine', 'elf_head_e_entry', 'elf_head_e_phoff', 'elf_head_e_shoff', 'elf_head_e_flags', 'elf_head_e_ehsize', 'elf_head_e_phentsize', 'elf_head_e_phnum', 'elf_head_e_shentsize', 'elf_head_e_shnum', 'elf_head_e_shstrndx', 'seg0_head_p_type', 'seg0_PT_LOAD_p_offset', 'seg0_PT_LOAD_p_filesz', 'seg0_PT_LOAD_p_memsz', 'seg0_PT_LOAD_p_flags', 'seg0_PT_LOAD_p_align', 'seg0_PT_LOAD_p_vaddr', 'seg0_PT_LOAD_p_paddr', 'seg1_head_p_type', 'seg1_PT_LOAD_p_offset', 'seg1_PT_LOAD_p_filesz', 'seg1_PT_LOAD_p_memsz', 'seg1_PT_LOAD_p_flags', 'seg1_PT_LOAD_p_align', 'seg1_PT_LOAD_p_vaddr', 'seg1_PT_LOAD_p_paddr', 'seg2_head_p_type', 'seg2_PT_GNU_STACK_p_offset', 'seg2_PT_GNU_STACK_p_filesz', 'seg2_PT_GNU_STACK_p_memsz', 'seg2_PT_GNU_STACK_p_flags', 'seg2_PT_GNU_STACK_p_align', 'seg2_PT_GNU_STACK_p_vaddr', 'seg2_PT_GNU_STACK_p_paddr', 'section__sh_name', 'section__sh_type', 'section__sh_flags', 'section__sh_addr', 'section__sh_offset', 'section__sh_size', 'section__sh_link', 'section__sh_info', 'section__sh_addralign', 'section__sh_entsize', 'section_init', 'section_init_sh_name', 'section_init_sh_type', 'section_init_sh_flags', 'section_init_sh_addr', 'section_init_sh_offset', 'section_init_sh_size', 'section_init_sh_link', 'section_init_sh_info', 'section_init_sh_addralign', 'section_init_sh_entsize', 'section_text', 'section_text_sh_name', 'section_text_sh_type', 'section_text_sh_flags', 'section_text_sh_addr', 'section_text_sh_offset', 'section_text_sh_size', 'section_text_sh_link', 'section_text_sh_info', 'section_text_sh_addralign', 'section_text_sh_entsize', 'section_fini', 'section_fini_sh_name', 'section_fini_sh_type', 'section_fini_sh_flags', 'section_fini_sh_addr', 'section_fini_sh_offset', 'section_fini_sh_size', 'section_fini_sh_link', 'section_fini_sh_info', 'section_fini_sh_addralign', 'section_fini_sh_entsize', 'section_rodata', 'section_rodata_sh_name', 'section_rodata_sh_type', 'section_rodata_sh_flags', 'section_rodata_sh_addr', 'section_rodata_sh_offset', 'section_rodata_sh_size', 'section_rodata_sh_link', 'section_rodata_sh_info', 'section_rodata_sh_addralign', 'section_rodata_sh_entsize', 'section_ctors', 'section_ctors_sh_name', 'section_ctors_sh_type', 'section_ctors_sh_flags', 'section_ctors_sh_addr', 'section_ctors_sh_offset', 'section_ctors_sh_size', 'section_ctors_sh_link', 'section_ctors_sh_info', 'section_ctors_sh_addralign', 'section_ctors_sh_entsize', 'section_dtors', 'section_dtors_sh_name', 'section_dtors_sh_type', 'section_dtors_sh_flags', 'section_dtors_sh_addr', 'section_dtors_sh_offset', 'section_dtors_sh_size', 'section_dtors_sh_link', 'section_dtors_sh_info', 'section_dtors_sh_addralign', 'section_dtors_sh_entsize', 'section_data', 'section_data_sh_name', 'section_data_sh_type', 'section_data_sh_flags', 'section_data_sh_addr', 'section_data_sh_offset', 'section_data_sh_size', 'section_data_sh_link', 'section_data_sh_info', 'section_data_sh_addralign', 'section_data_sh_entsize', 'section_bss', 'section_bss_sh_name', 'section_bss_sh_type', 'section_bss_sh_flags', 'section_bss_sh_addr', 'section_bss_sh_offset', 'section_bss_sh_size', 'section_bss_sh_link', 'section_bss_sh_info', 'section_bss_sh_addralign', 'section_bss_sh_entsize', 'section_shstrtab', 'section_shstrtab_sh_name', 'section_shstrtab_sh_type', 'section_shstrtab_sh_flags', 'section_shstrtab_sh_addr', 'section_shstrtab_sh_offset', 'section_shstrtab_sh_size', 'section_shstrtab_sh_link', 'section_shstrtab_sh_info', 'section_shstrtab_sh_addralign', 'section_shstrtab_sh_entsize']

    given_file = 'raw_data.csv'
    given_data = pd.read_csv(given_file)
    given_data_columns_list = []
    for i in given_data.columns.values:
            given_data_columns_list.append(i)
    for feature in features_list:
        if feature not in given_data_columns_list:
            # print("{} was not present, adding it to table with values 0...".format(feature))
            given_data[feature] = ''
    for feature in given_data_columns_list:
        if feature not in features_list:
            # print("{} was not present, removing it from table...".format(feature))
            given_data = given_data.drop(feature, axis=1)
    given_data.to_csv('examine_modified.csv', index=False)
    with open('examine_modified.csv', 'r') as infile, open('examine_reordered.csv', 'a' ,newline='') as outfile:
        fieldnames = features_list
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in csv.DictReader(infile):
            writer.writerow(row)
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
    clean_data['seg2_head_p_type'] = clean_data['seg2_head_p_type'].fillna(0)
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
    clean_data['dwarf_info_debug_info_sec_name'] = clean_data['dwarf_info_debug_info_sec_name'].replace({'.debug_info': 1})
    clean_data['dwarf_info_debug_aranges_sec_name'] = clean_data['dwarf_info_debug_aranges_sec_name'].replace({'.debug_aranges': 1})
    clean_data['dwarf_info_debug_abbrev_sec_name'] = clean_data['dwarf_info_debug_abbrev_sec_name'].replace({'.debug_abbrev': 1})
    clean_data['dwarf_info_debug_frame_sec_name'] = clean_data['dwarf_info_debug_frame_sec_name'].replace({'.debug_frame': 1})
    clean_data['dwarf_info_debug_str_sec_name'] = clean_data['dwarf_info_debug_str_sec_name'].replace({'.debug_str': 1})
    clean_data['dwarf_info_debug_loc_sec_name'] = clean_data['dwarf_info_debug_loc_sec_name'].replace({'.debug_loc': 1})
    clean_data['dwarf_info_debug_ranges_sec_name'] = clean_data['dwarf_info_debug_ranges_sec_name'].replace({'.debug_ranges': 1})
    clean_data['dwarf_info_debug_line_sec_name'] = clean_data['dwarf_info_debug_line_sec_name'].replace({'.debug_line': 1})
    # clean_data[''] = clean_data[''].replace({'.debug_frame': 1})
    clean_data['dwarf_info_debug_frame_sec_name'] = clean_data['dwarf_info_debug_frame_sec_name'].replace({'.debug_frame': 1})
    clean_data['dwarf_info_debug_frame_sec_name'] = clean_data['dwarf_info_debug_frame_sec_name'].replace({'.debug_frame': 1})
    clean_data['dwarf_info_debug_frame_sec_name'] = clean_data['dwarf_info_debug_frame_sec_name'].replace({'.debug_frame': 1})
    clean_data['dwarf_info_debug_pubtypes_sec_name'] = clean_data['dwarf_info_debug_pubtypes_sec_name'].fillna(0)
    clean_data['dwarf_info_debug_pubtypes_sec_global_offset'] = clean_data['dwarf_info_debug_pubtypes_sec_global_offset'].fillna(0)
    clean_data['dwarf_info_debug_pubtypes_sec_size'] = clean_data['dwarf_info_debug_pubtypes_sec_size'].fillna(0)
    clean_data['dwarf_info_debug_pubtypes_sec_address'] = clean_data['dwarf_info_debug_pubtypes_sec_address'].fillna(1)
    clean_data['dwarf_info_debug_pubnames_sec_name'] = clean_data['dwarf_info_debug_pubnames_sec_name'].replace({'.debug_pubnames': 1})
    clean_data['seg0_PT_LOAD_p_offset'] = clean_data['seg0_PT_LOAD_p_offset'].fillna(0)
    clean_data['seg0_PT_LOAD_p_filesz'] = clean_data['seg0_PT_LOAD_p_filesz'].fillna(0)
    clean_data['seg0_PT_LOAD_p_memsz'] = clean_data['seg0_PT_LOAD_p_memsz'].fillna(0)
    clean_data['seg0_PT_LOAD_p_flags'] = clean_data['seg0_PT_LOAD_p_flags'].fillna(0)
    clean_data['seg0_PT_LOAD_p_align'] = clean_data['seg0_PT_LOAD_p_align'].fillna(0)
    clean_data['seg0_PT_LOAD_p_vaddr'] = clean_data['seg0_PT_LOAD_p_vaddr'].fillna(0)
    clean_data['seg0_PT_LOAD_p_paddr'] = clean_data['seg0_PT_LOAD_p_paddr'].fillna(0)
    clean_data['seg1_head_p_type'] = clean_data['seg1_head_p_type'].replace({'PT_INTERP': 1, 'PT_LOAD': 2, 'PT_NOTE': 3, 'PT_PHDR': 4})
    clean_data['seg1_PT_LOAD_p_offset'] = clean_data['seg1_PT_LOAD_p_offset'].fillna(0)
    clean_data['seg1_PT_LOAD_p_filesz'] = clean_data['seg1_PT_LOAD_p_filesz'].fillna(0)
    clean_data['seg1_PT_LOAD_p_memsz'] = clean_data['seg1_PT_LOAD_p_memsz'].fillna(0)
    clean_data['seg1_PT_LOAD_p_flags'] = clean_data['seg1_PT_LOAD_p_flags'].fillna(0)
    clean_data['seg1_PT_LOAD_p_align'] = clean_data['seg1_PT_LOAD_p_align'].fillna(0)
    clean_data['seg1_PT_LOAD_p_vaddr'] = clean_data['seg1_PT_LOAD_p_vaddr'].fillna(0)
    clean_data['seg1_PT_LOAD_p_paddr'] = clean_data['seg1_PT_LOAD_p_paddr'].fillna(0)
    clean_data['seg2_head_p_type'] = clean_data['seg2_head_p_type'].replace({'PT_DYNAMIC': 1, 'PT_GNU_STACK': 2, 'PT_INTERP': 3, 'PT_LOAD': 4, 'PT_NOTE': 5, 'PT_TLS': 6})
    clean_data['seg2_PT_GNU_STACK_p_offset'] = clean_data['seg2_PT_GNU_STACK_p_offset'].fillna(0)
    clean_data['seg2_PT_GNU_STACK_p_filesz'] = clean_data['seg2_PT_GNU_STACK_p_filesz'].fillna(0)
    clean_data['seg2_PT_GNU_STACK_p_memsz'] = clean_data['seg2_PT_GNU_STACK_p_memsz'].fillna(0)
    clean_data['seg2_PT_GNU_STACK_p_flags'] = clean_data['seg2_PT_GNU_STACK_p_flags'].fillna(0)
    clean_data['seg2_PT_GNU_STACK_p_align'] = clean_data['seg2_PT_GNU_STACK_p_align'].fillna(0)
    clean_data['seg2_PT_GNU_STACK_p_vaddr'] = clean_data['seg2_PT_GNU_STACK_p_vaddr'].fillna(0)
    clean_data['seg2_PT_GNU_STACK_p_paddr'] = clean_data['seg2_PT_GNU_STACK_p_paddr'].fillna(0)
    clean_data['section__sh_type'] = clean_data['section__sh_type'].replace({'SHT_NULL': 1})
    clean_data['section_init'] = clean_data['section_init'].replace({1: 0, '.init': 1})
    clean_data['section_init_sh_type'] = clean_data['section_init_sh_type'].replace({'SHT_NOBITS': 1, 'SHT_PROGBITS': 2})
    clean_data['section_text'] = clean_data['section_text'].replace({'.text': 1})
    clean_data['section_text_sh_type'] = clean_data['section_text_sh_type'].replace({'SHT_NOBITS': 1, 'SHT_PROGBITS': 2})
    clean_data['section_fini'] = clean_data['section_fini'].replace({'.fini': 1})
    clean_data['section_fini_sh_type'] = clean_data['section_fini_sh_type'].replace({'SHT_NOBITS': 1, 'SHT_PROGBITS': 2})
    clean_data['section_rodata'] = clean_data['section_rodata'].replace({'.rodata': 1})
    clean_data['section_rodata_sh_type'] = clean_data['section_rodata_sh_type'].replace({'SHT_NOBITS': 1, 'SHT_PROGBITS': 2})
    clean_data['section_ctors'] = clean_data['section_ctors'].fillna(0)
    clean_data['section_ctors_sh_name'] = clean_data['section_ctors_sh_name'].fillna(0)
    clean_data['section_ctors_sh_type'] = clean_data['section_ctors_sh_type'].fillna(0)
    clean_data['section_ctors_sh_flags'] = clean_data['section_ctors_sh_flags'].fillna(0)
    clean_data['section_ctors_sh_addr'] = clean_data['section_ctors_sh_addr'].fillna(0)
    clean_data['section_ctors_sh_offset'] = clean_data['section_ctors_sh_offset'].fillna(0)
    clean_data['section_ctors_sh_size'] = clean_data['section_ctors_sh_size'].fillna(0)
    clean_data['section_ctors_sh_link'] = clean_data['section_ctors_sh_link'].fillna(0)
    clean_data['section_ctors_sh_info'] = clean_data['section_ctors_sh_info'].fillna(0)
    clean_data['section_ctors_sh_addralign'] = clean_data['section_ctors_sh_addralign'].fillna(0)
    clean_data['section_ctors_sh_entsize'] = clean_data['section_ctors_sh_entsize'].fillna(0)
    clean_data['section_dtors'] = clean_data['section_dtors'].fillna(0)
    clean_data['section_dtors_sh_name'] = clean_data['section_dtors_sh_name'].fillna(0)
    clean_data['section_dtors_sh_type'] = clean_data['section_dtors_sh_type'].fillna(0)
    clean_data['section_dtors_sh_flags'] = clean_data['section_dtors_sh_flags'].fillna(0)
    clean_data['section_dtors_sh_addr'] = clean_data['section_dtors_sh_addr'].fillna(0)
    clean_data['section_dtors_sh_offset'] = clean_data['section_dtors_sh_offset'].fillna(0)
    clean_data['section_dtors_sh_size'] = clean_data['section_dtors_sh_size'].fillna(0)
    clean_data['section_dtors_sh_link'] = clean_data['section_dtors_sh_link'].fillna(0)
    clean_data['section_dtors_sh_info'] = clean_data['section_dtors_sh_info'].fillna(0)
    clean_data['section_dtors_sh_addralign'] = clean_data['section_dtors_sh_addralign'].fillna(0)
    clean_data['section_dtors_sh_entsize'] = clean_data['section_dtors_sh_entsize'].fillna(0)
    clean_data['section_data'] = clean_data['section_data'].replace({'.data': 1})
    clean_data['section_data_sh_type'] = clean_data['section_data_sh_type'].replace({'SHT_NOBITS': 1, 'SHT_PROGBITS': 2})
    clean_data['section_bss'] = clean_data['section_bss'].replace({'.bss': 1})
    clean_data['section_bss_sh_type'] = clean_data['section_bss_sh_type'].replace({'SHT_NOBITS': 1})
    clean_data['section_shstrtab'] = clean_data['section_shstrtab'].replace({'.shstrtab': 1})
    clean_data['section_shstrtab_sh_type'] = clean_data['section_shstrtab_sh_type'].replace({'SHT_STRTAB': 1})
    clean_data['ehabi_infos'] = clean_data['ehabi_infos'].astype(bool).astype(int)

    clean_data.to_csv('perfect.csv', index=False)   # save the cleaned data to perfect.csv

# MODEL Training
# we have used the Random forest classifier to train the model, and saved the trained model as finalized_model.sav
# def train_model():
#     file1 = 'labelled_dataset.csv'
#     df = pd.read_csv(file1)
#     df = df.drop(['file_name'], axis=1)
#     features = df.columns.values
#     csv_features = []
#     for i in features:
#             csv_features.append(i)
#     print("features: {}".format(csv_features))
#     data = df[features[:-1]]
#     target = df[features[-1]]
#     X = data
#     Y = target
#     data_train, data_test, target_train, target_test = train_test_split(data, target, test_size=0.3, random_state=42)
#     rf = RandomForestClassifier()
#     rf.fit(data_train, target_train)
#     pred = rf.predict(data_test)
#     score = accuracy_score(target_test, pred, normalize=True)
#     print("F1 Score: {}%".format(f1_score(target_test, pred, average='macro')*100))
#     print("Accuracy: {}%".format(score*100))
#     filename = 'finalized_model.sav'
#     pickle.dump(rf, open(filename, 'wb'))

# PREDICTION
# function to take the cleaned data and predict the class of the ELF files
def predict_and_save():
    ready_data = pd.read_csv('perfect.csv')
    results = pd.DataFrame(ready_data['file_name'])
    results["FILENAME"] = results["file_name"]
    results.drop(['file_name'], axis=1, inplace=True)
    ready_data.drop('file_name', axis=1, inplace=True)
    loaded_model = pickle.load(open('finalized_model.sav', 'rb'))
    results['CLASS'] = pd.DataFrame(loaded_model.predict(ready_data))
    results['CLASS'] = results['CLASS'].str.upper()
    results.to_csv('result.csv', index=False)

try:
    info_dictionaries = []
    for filename in os.listdir(sys.argv[1]):
        info_dictionary = get_elf_info(sys.argv[1]+"/"+filename)
        info_dictionaries.append(info_dictionary)
    dict_to_csv(info_dictionaries, "raw_data.csv")
    clean_dataset()
    # train_model()
    predict_and_save()

except FileNotFoundError:
    print("specified files were not found...")

