#!/usr/bin/env python2

from pwn import *
from struct import unpack, pack
import sys
import os

MAGIC = '\x7f\x45\x4c\x46'
TYPE = None

def get_c_string(data, offset):
    out = ''
    while data[offset] != '\x00':
        out += data[offset]
        offset += 1
    return out

def parse_section(data):
    if TYPE == 64:
        return unpack('IIQQQQIIQQ', data)
    elif TYPE == 32:
        return unpack('IIIIIIIIII', data)

def parse_header(data):
    if TYPE == 64:
        return unpack('IIQQQQQQ', data)
    elif TYPE == 32:
        return unpack('IIIIIIII', data)

def parse_elf_header(data):
    if TYPE == 64:
        return unpack('16sHHIQQQIHHHHHH', data)
    elif TYPE == 32:
        return unpack('16sHHIIIIIHHHHHH', data)

def main(argv):
    global TYPE

    if len(argv) != 2:
        print 'usage: %s executable' % argv[0]
        return 1

    with open(argv[1], 'rb') as f:
        elf = f.read()

    context.os = 'linux'
    context.endianness = 'little'

    if elf[0:4] != MAGIC:
        sys.exit('[-] ELF magic not found')
    e_type = u8(elf[4:5])
    if e_type == 1:
        TYPE = 32
        context.bits = 32
        elf_header_size = u16(elf[0x28:0x2a])
        print '[*] 32 bits binary with elf_header_size %d' % elf_header_size
    elif e_type == 2:
        TYPE = 64
        context.bits = 64
        elf_header_size = u16(elf[0x34:0x36])
        print '[*] 64 bits binary with elf_header_size %d' % elf_header_size
    else:
        sys.exit('[-] Type could not be identified')

    ( e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, 
      e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
      e_shstrdnx ) = parse_elf_header(elf[:elf_header_size])

    if e_type != 2:
        sys.exit('[-] Binary is not an executable')

    str_table_index  = None
    str_table_offset = None
    sections         = []
    sections_dic     = {}
    headers          = []
    for i in xrange(e_phnum):
        s = parse_header(elf[e_phoff + i * e_phentsize:e_phoff + (i + 1) * e_phentsize])
        ( p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz,
          p_flags, p_align
        ) = s
        headers.append(s)

    # Adding sections to sections and finding the string table
    for i in xrange(e_shnum):
        s = parse_section(elf[e_shoff + i * e_shentsize:e_shoff + (i + 1) * e_shentsize])
        ( sh_name, sh_type, sh_flags, sh_addr, sh_offset,
          sh_size, sh_link, sh_info, sh_addralign, sh_entsize,
        ) = s
        sections.append(s)

        if sh_type == 3:
            if i != e_shstrdnx:
                continue
            str_table_index = e_shstrdnx
            str_table_offset = sh_offset

    if str_table_index != e_shstrdnx:
        sys.exit('[-] mismatch between str_table_index and e_shstrdnx')

    text_offset         = None
    text_size           = None
    last_strtable_index = -1
    
    for i in xrange(e_shnum):
        ( sh_name, sh_type, sh_flags, sh_addr, sh_offset,
          sh_size, sh_link, sh_info, sh_addralign, sh_entsize,
        ) = sections[i]

        name = get_c_string(elf, str_table_offset + sh_name)
        if name == '.text':
            text_offset = sh_offset
            text_size   = sh_size

        if sh_name + len(name) > last_strtable_index:
            last_strtable_index = sh_name + len(name)
        
        sections_dic[name] = s
        print i, name, hex(sh_offset)
    
    if (text_offset == None or text_size == None):
        sys.exit('[-] Could not find .text section')

    print '[*] Found .text section at %#x of size %#x' % (sh_offset, sh_size)

    packed = bytearray(elf)
    for i in xrange(text_size):
        packed[text_offset + i] ^= 0xa5

    # Now adding one section for our dynamic unpacker
    new_section_name = '.code\x00'

    # inserting our new section's name in .shstrtab
    packed = packed[:last_strtable_index + str_table_offset + 1] + '.code\x00' \
             + packed[last_strtable_index + str_table_offset + 1:]

    # shifting by len(new_section_name) e_shoff
    # also adding one more section
    if TYPE == 32:
        packed[0x20:0x24] = p32(e_shoff + len(new_section_name))
        packed[0x30:0x32] = p16(e_shnum + 1)
    elif TYPE == 64:
        packed[0x28:0x30] = p64(e_shoff + len(new_section_name))
        packed[0x3c:0x3e] = p16(e_shnum + 1)
    e_shoff += len(new_section_name)

    # moving other sections of len(new_section_name)
    for i in xrange(e_shstrdnx + 1, e_shnum):
        ( sh_name, sh_type, sh_flags, sh_addr, sh_offset,
          sh_size, sh_link, sh_info, sh_addralign, sh_entsize,
        ) = sections[i]
        offset = e_shoff + e_shentsize * i
        if TYPE == 32:
            offset += 0x14
            packed[offset:offset + 4] = p32(sh_size + len(new_section_name))
        elif TYPE == 64:
            offset += 0x20
            packed[offset:offset + 8] = p64(sh_size + len(new_section_name))
    
    # TODO: add the section
    new_section = 0
        
    with open(argv[1] + '.packed', 'wb') as f:
        f.write(packed)

    print '[*] packed program wrote to %s' % (argv[1] + '.packed')

if __name__ == '__main__':
    sys.exit(main(sys.argv))
