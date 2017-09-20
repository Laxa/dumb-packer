#!/usr/bin/env python2

from pwn import *
from struct import unpack, pack
import argparse
import sys
import os

DEBUG = True
MAGIC = '\x7f\x45\x4c\x46'
TYPE = None

def get_c_string(data, offset):
    out = ''
    while data[offset] != '\x00':
        out += data[offset]
        offset += 1
    return out

def parse_section(data):
    if TYPE == 32:
        return unpack('IIIIIIIIII', data)
    elif TYPE == 64:
        return unpack('IIQQQQIIQQ', data)

def parse_header(data):
    if TYPE == 32:
        return unpack('IIIIIIII', data)
    elif TYPE == 64:
        return unpack('IIQQQQQQ', data)

def parse_elf_header(data):
    if TYPE == 32:
        return unpack('16sHHIIIIIHHHHHH', data)
    elif TYPE == 64:
        return unpack('16sHHIQQQIHHHHHH', data)

def get_unpacker(e_entry, text_size, xor_key):
    e_entry_aligned = e_entry & 0xfffffffffffff000
    test_size_aligned = text_size
    if text_size & 0xfff:
        test_size_aligned = (text_size & 0xfffffffffffff000) + 0x1000
    if TYPE == 32:
        raise NotImplementedError()
    elif TYPE == 64:
        unpacker = asm('''
        push rax
        push rdi
        push rsi
        push rdx
        push rcx

        mov rdi, ''' + hex(e_entry_aligned)   + '''
        mov rsi, ''' + hex(test_size_aligned) + '''
        mov rdx, 7
        mov rax, 10
        syscall

        mov rdi, ''' + hex(e_entry)  + '''
        mov rsi, rdi
        mov rcx, ''' + hex(text_size) + '''

        cld
        decrypt:
          lodsb
          xor al, ''' + hex(xor_key) + '''
          stosb
          loop decrypt

        pop rcx
        pop rdx
        pop rsi
        pop rdi
        pop rax

        push ''' + hex(e_entry) + '''
        ret
        ''')
    return unpacker

def main(binary, xor_key):
    global TYPE

    with open(binary, 'rb') as f:
        elf = f.read()

    context.os = 'linux'
    context.endianness = 'little'
    # Only supporting 1 byte key
    xor_key &= 0xff

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
    max_vaddr           = -1
    max_section_offset  = -1
    last_strtable_index = -1

    for i in xrange(e_shnum):
        ( sh_name, sh_type, sh_flags, sh_addr, sh_offset,
          sh_size, sh_link, sh_info, sh_addralign, sh_entsize,
        ) = sections[i]

        print 'Getting c_string at %#x' % (str_table_offset + sh_name)
        name = get_c_string(elf, str_table_offset + sh_name)
        if name == '.text':
            text_offset = sh_offset
            text_size   = sh_size
            if DEBUG:
                print '[*] Found .text offset at %#x of size %#x' % (text_offset, text_size)

        if sh_name + len(name) > last_strtable_index:
            last_strtable_index = sh_name + len(name)

        if sh_addr + sh_size > max_vaddr and sh_flags & 2 and sh_addr != 0:
            max_vaddr = sh_addr + sh_size
        if sh_offset + sh_size > max_section_offset and sh_flags & 2 and sh_addr != 0:
            max_section_offset = sh_offset + sh_size
        
        sections_dic[name] = s

        if DEBUG:
            print i, name, hex(sh_offset)
            print ( sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                    sh_size, sh_link, sh_info, sh_addralign, sh_entsize )

    if (text_offset == None or text_size == None):
        sys.exit('[-] Could not find .text section')

    if DEBUG:
        print '[*] Max vaddr offset: %#x' % max_vaddr
        print '[*] Max section offset: %#x' % max_section_offset
        print '[*] last_strtable_index %#x' % last_strtable_index
    print '[*] Found .text section at %#x of size %#x' % (sh_offset, sh_size)

    packed = bytearray(elf)
    for i in xrange(text_size):
        packed[text_offset + i] ^= xor_key

    # Generating our unpacker
    new_section_name = '.code\x00'
    unpacker = get_unpacker(e_entry, text_size, xor_key)

    section_vaddr = (max_vaddr & 0xfffffffffffff000) + 0x1000
    section_size = len(unpacker)
    print '[*] New section vaddr: %#x' % section_vaddr
    print '[*] Unpacker size: %#x'     % section_size

    # Updating ELF header
    # adding section_vaddr to eop
    if TYPE == 32:
        packed[0x18:0x1c] = p32(section_vaddr)
    elif TYPE == 64:
        packed[0x18:0x20] = p64(section_vaddr)

    # shifting by len(new_section_name) e_shoff
    # also adding one more section
    if TYPE == 32:
        packed[0x20:0x24] = p32(e_shoff + len(new_section_name) + len(unpacker) + e_phentsize)
        packed[0x30:0x32] = p16(e_shnum + 1)
    elif TYPE == 64:
        packed[0x28:0x30] = p64(e_shoff + len(new_section_name) + len(unpacker) + e_phentsize)
        packed[0x3c:0x3e] = p16(e_shnum + 1)
    e_shoff += len(new_section_name)

    # Getting header because we will shift everything
    # We need also a new header for our .code segment
    # new layout should be like this:
    # ------------------------
    # |      ELF Header      |
    # ------------------------
    # |   program Headers    |
    # |  new program header  |
    # ------------------------
    # |       sections       |
    # ------------------------
    # |    our new section   |
    # ------------------------
    # |    section headers   |
    # |our new section header|
    # ------------------------
    headers           = []
    max_header_offset = None
    for i in xrange(e_phnum):
        # p_flags offset is different in 32 and 64 bits
        if TYPE == 32:
            s = parse_header(elf[e_phoff + i * e_phentsize:e_phoff + (i + 1) * e_phentsize])
            ( p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align ) = s
        elif TYPE == 64:
            s = parse_header(elf[e_phoff + i * e_phentsize:e_phoff + (i + 1) * e_phentsize])
            ( p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align ) = s
        if DEBUG:
            print s
        if i + 1 == e_phnum:
            max_header_offset = e_phoff + (i + 1) * e_phentsize
        headers.append(s)
    if DEBUG:
        print '[*] Max program header at %#x' % max_header_offset

    new_program_header = ''
    if TYPE == 32:
        # p_type
        new_program_header += p32(1) # PT_LOAD
        # p_offset
        new_program_header += p32(max_section_offset + len(new_section_name))
        # p_vaddr
        new_program_header += p32(section_vaddr)
        # p_paddr
        new_program_header += p32(section_vaddr)
        # p_filesz
        new_program_header += p32(len(unpacker))
        # p_memsz
        new_program_header += p32(len(unpacker))
        # p_flags
        new_program_header += p32(0x5) # READ | EXECUTE
        # p_align
        new_program_header += p64(0x1000)
    elif TYPE == 64:
        # p_type
        new_program_header += p32(1) # PT_LOAD
        # p_flags
        new_program_header += p32(5) # READ | EXECUTE
        # p_offset
        new_program_header += p64(max_section_offset + len(new_section_name))
        # p_vaddr
        new_program_header += p64(section_vaddr)
        # p_paddr
        new_program_header += p64(section_vaddr)
        # p_filesz
        new_program_header += p64(len(unpacker))
        # p_memsz
        new_program_header += p64(len(unpacker))
        # p_align
        new_program_header += p64(0x1000)

    # adding our new program header
    packed = packed[:max_header_offset] + new_program_header + packed[max_header_offset:]
    # increasing e_phnum
    if TYPE == 32:
        packed[0x2c:0x2e] = p16(e_phnum + 1)
    elif TYPE == 64:
        packed[0x38:0x3a] = p16(e_phnum + 1)

    # Now adding one section for our dynamic unpacker
    new_section_name_offset = last_strtable_index + str_table_offset + 1 + e_phentsize
    # increasing e_shoff for following operations
    e_shoff += e_phentsize

    # inserting our new section's name in .shstrtab
    packed = packed[:new_section_name_offset] + '.code\x00' \
             + packed[new_section_name_offset:]

    # increasing .shstrtab size
    if TYPE == 32:
        shstrab_size_offset = e_shoff + (e_shstrdnx * e_shentsize) + 0x14
        shtrab_size_size = u32(packed[shstrab_size_offset:shstrab_size_offset+4])
        packed[shstrab_size_offset:shstrab_size_offset+4] = p32(shtrab_size_size
         + len(new_section_name))
    elif TYPE == 64:
        shstrab_size_offset = e_shoff + (e_shstrdnx * e_shentsize) + 0x20
        shtrab_size_size = u64(packed[shstrab_size_offset:shstrab_size_offset+8])
        packed[shstrab_size_offset:shstrab_size_offset+8] = p64(shtrab_size_size
         + len(new_section_name))

    # moving other sections of len(new_section_name)
    for i in xrange(0, e_shnum):
        ( sh_name, sh_type, sh_flags, sh_addr, sh_offset,
          sh_size, sh_link, sh_info, sh_addralign, sh_entsize,
        ) = sections[i]
        new_offset = sh_offset + e_phentsize
        # for section after .shstrtab, we also increase by new_section_name
        if i > e_shstrdnx:
            new_offset += len(new_section_name)
        offset = e_shoff + e_shentsize * i
        if TYPE == 32:
            offset += 0x10
            packed[offset:offset + 4] = p32(new_offset)
        elif TYPE == 64:
            offset += 0x18
            packed[offset:offset + 8] = p64(new_offset)

    # adding new section
    if TYPE == 32:
        # sh_name
        new_section  = p32(last_strtable_index + 1)
        # sh_type
        new_section += p32(1) # SHT_PROGBITS
        # sh_flags
        new_section += p32(6) # SHF_ALLOC | SHF_EXECINSTR
        # sh_addr
        new_section += p32(section_vaddr)
        # sh_offset
        new_section += p32(e_shentsize + len(packed))
        # sh_size
        new_section += p32(section_size)
        # sh_link
        new_section += p32(0)
        # sh_info
        new_section += p32(0)
        # sh_addralign
        new_section += p32(16)
        # sh_entsize
        new_section += p32(0)
    elif TYPE == 64:
        # sh_name
        new_section  = p32(last_strtable_index + 1)
        # sh_type
        new_section += p32(1) # SHT_PROGBITS
        # sh_flags
        new_section += p64(6) # SHF_ALLOC | SHF_EXECINSTR
        # sh_addr
        new_section += p64(section_vaddr)
        # sh_offset
        new_section += p64(e_shentsize + len(packed))
        # sh_size
        new_section += p64(section_size)
        # sh_link
        new_section += p32(0)
        # sh_info
        new_section += p32(0)
        # sh_addralign
        new_section += p64(16)
        # sh_entsize
        new_section += p64(0)

    new_section_offset = e_shentsize + max_section_offset
    print '[*] New section code is at: %#x' % new_section_offset
    # adding unpacker as last section
    packed = packed[:new_section_offset] + unpacker + packed[new_section_offset:]

    # adding our section
    packed += new_section

    with open(binary + '.packed', 'wb') as f:
        f.write(packed)

    print '[*] packed program wrote to %s' % (binary + '.packed')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', help='binary to pack')
    parser.add_argument('-k', '--key', help='byte value for xoring .txt section',
                        default=0xa5)
    args = parser.parse_args()

    sys.exit(main(args.binary, args.key))
