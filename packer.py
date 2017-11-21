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

    if DEBUG:
        print '[*] e_shstrdnx: %d' % e_shstrdnx

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

        if DEBUG:
            for x in s:
                sys.stdout.write(hex(x) + ', ')
            sys.stdout.write('\n')

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
            text_vaddr  = sh_addr
            text_section_index = i
            if DEBUG:
                print '[*] Found .text offset at %#x of size %#x' % (text_offset, text_size)

        if sh_name + len(name) > last_strtable_index:
            last_strtable_index = sh_name + len(name)

        if sh_addr + sh_size > max_vaddr and sh_flags & 2 and sh_addr != 0:
            max_vaddr = sh_addr + sh_size
        
        sections_dic[name] = s

        if DEBUG:
            print i, name, hex(sh_offset)
            for x in s:
                    sys.stdout.write(hex(x) + ', ')
            sys.stdout.write('\n')

    if (text_offset == None or text_size == None):
        sys.exit('[-] Could not find .text section')

    if DEBUG:
        print '[*] Max vaddr offset: %#x' % max_vaddr
        print '[*] last_strtable_index %#x' % last_strtable_index
    print '[*] Found .text section at %#x of size %#x' % (sh_offset, text_size)

    # Start of modifications of the binary

    packed = bytearray(elf)
    for i in xrange(text_size):
        packed[text_offset + i] ^= xor_key

    unpacker = get_unpacker(e_entry, text_size, xor_key)
    # adding unpacker to the binary
    unpacker_offset = text_offset + text_size
    packed =    packed[:unpacker_offset] + \
                unpacker + \
                packed[unpacker_offset:]

    # Generating our unpacker
    new_section_name = '.code\x00'
    new_section_offset =    e_shoff + e_shentsize * (text_section_index + 1) + \
                            len(unpacker) + len(new_section_name)

    packer_section_vaddr = text_vaddr + text_size
    packer_section_size = len(unpacker)
    print '[*] New section vaddr: %#x' % packer_section_vaddr
    print '[*] Unpacker size: %#x'     % packer_section_size

    # Updating ELF header
    # adding section_vaddr to eop
    if TYPE == 32:
        packed[0x18:0x1c] = p32(packer_section_vaddr)
    elif TYPE == 64:
        packed[0x18:0x20] = p64(packer_section_vaddr)

    e_shoff += len(new_section_name) + len(unpacker)
    # shifting by len(new_section_name) e_shoff
    # also adding one more section
    if TYPE == 32:
        packed[0x20:0x24] = p32(e_shoff)
        packed[0x30:0x32] = p16(e_shnum + 1)
    elif TYPE == 64:
        packed[0x28:0x30] = p64(e_shoff)
        packed[0x3c:0x3e] = p16(e_shnum + 1)

    if (text_section_index + 1 < e_shstrdnx):
        if TYPE == 32:
            packed[0x32:0x36] = p16(e_shstrdnx + 1)
        elif TYPE == 64:
            packed[0x3e:0x40] = p16(e_shstrdnx + 1)

    # Now adding one section for our dynamic unpacker
    new_section_name_offset = last_strtable_index + str_table_offset + 1 + len(unpacker)

    # inserting our new section's name in .shstrtab
    packed = packed[:new_section_name_offset] + '.code\x00' \
             + packed[new_section_name_offset:]

    # Getting headers because we will shift everything
    # We need also a new header for our .code segment
    # new layout should be like this:
    # ------------------------
    # |      ELF Header      |
    # ------------------------
    # |   program Headers    |
    # ------------------------
    # |  sections til text   |
    # ------------------------
    # |    our new section   |
    # ------------------------
    # |   rest of sections   |
    # ------------------------
    # |    section headers   |
    # |our new section header|
    # ------------------------
    headers           = []
    shift = False
    for i in xrange(e_phnum):
        # p_flags offset is different in 32 and 64 bits
        target_offset = e_phoff + i * e_phentsize
        if TYPE == 32:
            s = parse_header(elf[target_offset:target_offset + e_phentsize])
            ( p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align ) = s
            # shifting offsets for other program headers
            if shift and p_offset > text_offset:
                packed[target_offset + 0x4:target_offset + 0x8] = p32(p_offset + packer_section_size)
            if shift and p_offset != 0 and (p_vaddr > code_section_vaddr and p_vaddr < code_section_maxvaddr):
                packed[target_offset + 0x8:target_offset + 0xc] = p32(p_vaddr + packer_section_size)
                packed[target_offset + 0xc:target_offset + 0x10] = p32(p_paddr + packer_section_size)
            if p_flags == 0x5 and p_offset == 0:
                print 'Found LOAD_SEGMENT for code at %#x' % (target_offset)
                packed[target_offset + 0x10:target_offset + 0x14] = p32(p_filesz + packer_section_size)
                packed[target_offset + 0x14:target_offset + 0x18] = p32(p_memsz + packer_section_size)
                shift = True
                code_section_vaddr = p_vaddr
                code_section_maxvaddr = p_vaddr + p_align
            
        elif TYPE == 64:
            s = parse_header(elf[target_offset:target_offset + e_phentsize])
            ( p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align ) = s
            # shifting offsets for other program headers
            if shift and p_offset > text_offset:
                packed[target_offset + 0x8:target_offset + 0x10] = p64(p_offset + packer_section_size)
            if shift and p_offset != 0 and (p_vaddr > code_section_vaddr and p_vaddr < code_section_maxvaddr):
                packed[target_offset + 0x10:target_offset + 0x18] = p64(p_vaddr + packer_section_size)
                packed[target_offset + 0x18:target_offset + 0x20] = p64(p_paddr + packer_section_size)
            if p_flags == 0x5 and p_offset == 0:
                print 'Found LOAD_SEGMENT for code at %#x' % (target_offset)
                packed[target_offset + 0x20:target_offset + 0x28] = p64(p_filesz + packer_section_size)
                packed[target_offset + 0x28:target_offset + 0x30] = p64(p_memsz + packer_section_size)
                shift = True
                code_section_vaddr = p_vaddr
                code_section_maxvaddr = p_vaddr + p_align

        headers.append(s)

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
    for i in xrange(text_section_index + 1, e_shnum):
        ( sh_name, sh_type, sh_flags, sh_addr, sh_offset,
          sh_size, sh_link, sh_info, sh_addralign, sh_entsize,
        ) = sections[i]
        new_offset = sh_offset + len(unpacker)
        new_vaddr = sh_addr
        if (sh_addr != 0 and sh_addr < code_section_maxvaddr):
            new_vaddr += len(unpacker)
        # for section after .shstrtab, we also increase by new_section_name
        if i > e_shstrdnx:
            new_offset += len(new_section_name)
        offset = e_shoff + e_shentsize * i
        if TYPE == 32:
            offset += 0xc
            packed[offset:offset + 4] = p32(new_vaddr)
            offset += 0x4
            packed[offset:offset + 4] = p32(new_offset)
            if sh_link > text_section_index:
                offset += 0x8
                packed[offset:offset + 4] = p32(sh_link + 1)
        elif TYPE == 64:
            offset += 0x10
            packed[offset:offset + 8] = p64(new_vaddr)
            offset += 0x8
            packed[offset:offset + 8] = p64(new_offset)
            if sh_link > text_section_index:
                offset += 0x10
                packed[offset:offset + 4] = p32(sh_link + 1)

    # adding new section
    if TYPE == 32:
        # sh_name
        new_section  = p32(last_strtable_index + 1)
        # sh_type
        new_section += p32(1) # SHT_PROGBITS
        # sh_flags
        new_section += p32(6) # SHF_ALLOC | SHF_EXECINSTR
        # sh_addr
        new_section += p32(packer_section_vaddr)
        # sh_offset
        new_section += p32(unpacker_offset)
        # sh_size
        new_section += p32(packer_section_size)
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
        new_section += p64(packer_section_vaddr)
        # sh_offset
        new_section += p64(unpacker_offset)
        # sh_size
        new_section += p64(packer_section_size)
        # sh_link
        new_section += p32(0)
        # sh_info
        new_section += p32(0)
        # sh_addralign
        new_section += p64(16)
        # sh_entsize
        new_section += p64(0)

    print '[*] New code section is at: %#x' % new_section_offset
    # adding unpacker section
    packed = packed[:new_section_offset] + new_section + packed[new_section_offset:]

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
