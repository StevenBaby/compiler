'''
(C) Copyright 2021 Steven;
@author: Steven kangweibaby@163.com
@date: 2021-07-13
'''

# coding=utf-8

import ctypes
import struct
import types
import unittest
from io import BytesIO

from ctypes import Structure, sizeof
from typing import *

from common import *
from logger import logger

'''
定义基础数据类型
# include <elf.h>
'''

Elf32_Half = u16
Elf64_Half = u16

Elf32_Word = u32
Elf32_Sword = u32
Elf64_Word = u32
Elf64_Sword = u32

Elf32_Xword = u64
Elf32_Sxword = u64
Elf32_Sxword = u64
Elf64_Sxword = u64

Elf32_Addr = u32
Elf64_Addr = u64

Elf32_Off = u32
Elf64_Off = u64

Elf32_Section = u16
Elf64_Section = u16

Elf32_Versym = u32
Elf64_Versym = u64


# 用于替换 C 结构体定义的正则
# .+(Elf.+)\t(.+_.+);.*
# ('$2', $1),

# 用于替换 C 常量定义的正则
# #define(.+?)[ \t]+([\da-fx]+)[\s]*(?:/\*([\w\W]+?)\*/)?
# $1 = $2 # $3

class Constant(object):

    @classmethod
    def get_name(cls, value):
        if not hasattr(cls, 'NAMES'):
            cls.NAMES = {}
            for name in dir(cls):
                var = getattr(cls, name)
                if isinstance(var, (int, str)):
                    cls.NAMES[var] = name
        if value in cls.NAMES:
            return cls.NAMES[value]
        return "undefined"


class BaseStructure(ctypes.LittleEndianStructure):

    _pack_ = 1  # 表示对齐
    _fields_ = []


class BaseUnion(ctypes.Union):

    _pack_ = 1
    _fields_ = []


class ElfIdent(BaseStructure):

    _fields_ = [
        ('ei_magic', u32),
        ('ei_class', u8),
        ('ei_data', u8),
        ('ei_version', u8),
        ('ei_pad', u8),
        ('ei_nident', u8 * 8),
    ]

    # /* Conglomeration of the identification bytes, for easy testing as a word.  */
    class MAGIC(Constant):
        ELFMAG = "\177ELF"
        SELFMAG = 4

    class CLASS(Constant):

        EI_CLASS = 4		 # File class byte index
        ELFCLASSNONE = 0		 # Invalid class
        ELFCLASS32 = 1		 # 32-bit objects
        ELFCLASS64 = 2		 # 64-bit objects
        ELFCLASSNUM = 3

    class DATA(Constant):

        EI_DATA = 5      # Data encoding byte index
        ELFDATANONE = 0  # Invalid data encoding
        ELFDATA2LSB = 1  # 2's complement, little endian
        ELFDATA2MSB = 2  # 2's complement, big endian
        ELFDATANUM = 3


class Elf32_Ehdr(BaseStructure):

    _fields_ = [
        ('e_ident', ElfIdent),
        ('e_type', Elf32_Half),
        ('e_machine', Elf32_Half),
        ('e_version', Elf32_Word),
        ('e_entry', Elf32_Addr),
        ('e_phoff', Elf32_Off),
        ('e_shoff', Elf32_Off),
        ('e_flags', Elf32_Word),
        ('e_ehsize', Elf32_Half),
        ('e_phentsize', Elf32_Half),
        ('e_phnum', Elf32_Half),
        ('e_shentsize', Elf32_Half),
        ('e_shnum', Elf32_Half),
        ('e_shstrndx', Elf32_Half),
    ]

    class ET(Constant):
        # e_type
        ET_NONE = 0         # No file type
        ET_REL = 1          # Relocatable file
        ET_EXEC = 2         # Executable file
        ET_DYN = 3          # Shared object file
        ET_CORE = 4         # Core file
        ET_NUM = 5          # Number of defined types
        ET_LOOS = 0xfe00    # OS-specific range start
        ET_HIOS = 0xfeff    # OS-specific range end
        ET_LOPROC = 0xff00  # Processor-specific range start
        ET_HIPROC = 0xffff  # Processor-specific range end

    class EM(Constant):
        # e_machine
        EM_NONE = 0  # No machine
        EM_M32 = 1  # AT&T WE 32100
        EM_SPARC = 2	 # SUN SPARC
        EM_386 = 3  # Intel 80386
        EM_68K = 4  # Motorola m68k family
        EM_88K = 5  # Motorola m88k family
        EM_IAMCU = 6	 # Intel MCU
        EM_860 = 7  # Intel 80860
        EM_MIPS = 8  # MIPS R3000 big-endian
        EM_S370 = 9  # IBM System/370
        EM_MIPS_RS3_LE = 10	 # MIPS R3000 little-endian
        # reserved 11-14
        EM_PARISC = 15	 # HPPA
        # reserved 16
        EM_VPP500 = 17	 # Fujitsu VPP500
        EM_SPARC32PLUS = 18	 # Sun's "v8plus"
        EM_960 = 19  # Intel 80960
        EM_PPC = 20  # PowerPC
        EM_PPC64 = 21	 # PowerPC 64-bit
        EM_S390 = 22  # IBM S390
        EM_SPU = 23  # IBM SPU/SPC
        # reserved 24-35
        EM_V800 = 36  # NEC V800 series
        EM_FR20 = 37  # Fujitsu FR20
        EM_RH32 = 38  # TRW RH-32
        EM_RCE = 39  # Motorola RCE
        EM_ARM = 40  # ARM
        EM_FAKE_ALPHA = 41	 # Digital Alpha
        EM_SH = 42  # Hitachi SH
        EM_SPARCV9 = 43	 # SPARC v9 64-bit
        EM_TRICORE = 44	 # Siemens Tricore
        EM_ARC = 45  # Argonaut RISC Core
        EM_H8_300 = 46	 # Hitachi H8/300
        EM_H8_300H = 47	 # Hitachi H8/300H
        EM_H8S = 48  # Hitachi H8S
        EM_H8_500 = 49	 # Hitachi H8/500
        EM_IA_64 = 50	 # Intel Merced
        EM_MIPS_X = 51	 # Stanford MIPS-X
        EM_COLDFIRE = 52	 # Motorola Coldfire
        EM_68HC12 = 53	 # Motorola M68HC12
        EM_MMA = 54  # Fujitsu MMA Multimedia Accelerator
        EM_PCP = 55  # Siemens PCP
        EM_NCPU = 56  # Sony nCPU embeeded RISC
        EM_NDR1 = 57  # Denso NDR1 microprocessor
        EM_STARCORE = 58	 # Motorola Start*Core processor
        EM_ME16 = 59  # Toyota ME16 processor
        EM_ST100 = 60	 # STMicroelectronic ST100 processor
        EM_TINYJ = 61	 # Advanced Logic Corp. Tinyj emb.fam
        EM_X86_64 = 62	 # AMD x86-64 architecture
        EM_PDSP = 63  # Sony DSP Processor
        EM_PDP10 = 64	 # Digital PDP-10
        EM_PDP11 = 65	 # Digital PDP-11
        EM_FX66 = 66  # Siemens FX66 microcontroller
        EM_ST9PLUS = 67	 # STMicroelectronics ST9+ 8/16 mc
        EM_ST7 = 68  # STmicroelectronics ST7 8 bit mc
        EM_68HC16 = 69	 # Motorola MC68HC16 microcontroller
        EM_68HC11 = 70	 # Motorola MC68HC11 microcontroller
        EM_68HC08 = 71	 # Motorola MC68HC08 microcontroller
        EM_68HC05 = 72	 # Motorola MC68HC05 microcontroller
        EM_SVX = 73  # Silicon Graphics SVx
        EM_ST19 = 74  # STMicroelectronics ST19 8 bit mc
        EM_VAX = 75  # Digital VAX
        EM_CRIS = 76  # Axis Communications 32-bit emb.proc
        EM_JAVELIN = 77	 # Infineon Technologies 32-bit emb.proc
        EM_FIREPATH = 78	 # Element 14 64-bit DSP Processor
        EM_ZSP = 79  # LSI Logic 16-bit DSP Processor
        EM_MMIX = 80  # Donald Knuth's educational 64-bit proc
        EM_HUANY = 81	 # Harvard University machine-independent object files
        EM_PRISM = 82	 # SiTera Prism
        EM_AVR = 83  # Atmel AVR 8-bit microcontroller
        EM_FR30 = 84  # Fujitsu FR30
        EM_D10V = 85  # Mitsubishi D10V
        EM_D30V = 86  # Mitsubishi D30V
        EM_V850 = 87  # NEC v850
        EM_M32R = 88  # Mitsubishi M32R
        EM_MN10300 = 89	 # Matsushita MN10300
        EM_MN10200 = 90	 # Matsushita MN10200
        EM_PJ = 91  # picoJava
        EM_OPENRISC = 92	 # OpenRISC 32-bit embedded processor
        EM_ARC_COMPACT = 93	 # ARC International ARCompact
        EM_XTENSA = 94	 # Tensilica Xtensa Architecture
        EM_VIDEOCORE = 95	 # Alphamosaic VideoCore
        EM_TMM_GPP = 96	 # Thompson Multimedia General Purpose Proc
        EM_NS32K = 97	 # National Semi. 32000
        EM_TPC = 98  # Tenor Network TPC
        EM_SNP1K = 99	 # Trebia SNP 1000
        EM_ST200 = 100	 # STMicroelectronics ST200
        EM_IP2K = 101  # Ubicom IP2xxx
        EM_MAX = 102  # MAX processor
        EM_CR = 103  # National Semi. CompactRISC
        EM_F2MC16 = 104	 # Fujitsu F2MC16
        EM_MSP430 = 105	 # Texas Instruments msp430
        EM_BLACKFIN = 106	 # Analog Devices Blackfin DSP
        EM_SE_C33 = 107	 # Seiko Epson S1C33 family
        EM_SEP = 108  # Sharp embedded microprocessor
        EM_ARCA = 109  # Arca RISC
        EM_UNICORE = 110	 # PKU-Unity & MPRC Peking Uni. mc series
        EM_EXCESS = 111	 # eXcess configurable cpu
        EM_DXP = 112  # Icera Semi. Deep Execution Processor
        EM_ALTERA_NIOS2 = 113  # Altera Nios II
        EM_CRX = 114  # National Semi. CompactRISC CRX
        EM_XGATE = 115	 # Motorola XGATE
        EM_C166 = 116  # Infineon C16x/XC16x
        EM_M16C = 117  # Renesas M16C
        EM_DSPIC30F = 118	 # Microchip Technology dsPIC30F
        EM_CE = 119  # Freescale Communication Engine RISC
        EM_M32C = 120  # Renesas M32C
        # reserved 121-130
        EM_TSK3000 = 131	 # Altium TSK3000
        EM_RS08 = 132  # Freescale RS08
        EM_SHARC = 133	 # Analog Devices SHARC family
        EM_ECOG2 = 134	 # Cyan Technology eCOG2
        EM_SCORE7 = 135	 # Sunplus S+core7 RISC
        EM_DSP24 = 136	 # New Japan Radio (NJR) 24-bit DSP
        EM_VIDEOCORE3 = 137	 # Broadcom VideoCore III
        EM_LATTICEMICO32 = 138  # RISC for Lattice FPGA
        EM_SE_C17 = 139         # Seiko Epson C17
        EM_TI_C6000 = 140       # Texas Instruments TMS320C6000 DSP
        EM_TI_C2000 = 141       # Texas Instruments TMS320C2000 DSP
        EM_TI_C5500 = 142       # Texas Instruments TMS320C55x DSP
        EM_TI_ARP32 = 143       # Texas Instruments App. Specific RISC
        EM_TI_PRU = 144	 # Texas Instruments Prog. Realtime Unit
        # reserved 145-159
        EM_MMDSP_PLUS = 160	 # STMicroelectronics 64bit VLIW DSP
        EM_CYPRESS_M8C = 161	 # Cypress M8C
        EM_R32C = 162  # Renesas R32C
        EM_TRIMEDIA = 163	 # NXP Semi. TriMedia
        EM_QDSP6 = 164	 # QUALCOMM DSP6
        EM_8051 = 165  # Intel 8051 and variants
        EM_STXP7X = 166	 # STMicroelectronics STxP7x
        EM_NDS32 = 167	 # Andes Tech. compact code emb. RISC
        EM_ECOG1X = 168	 # Cyan Technology eCOG1X
        EM_MAXQ30 = 169	 # Dallas Semi. MAXQ30 mc
        EM_XIMO16 = 170	 # New Japan Radio (NJR) 16-bit DSP
        EM_MANIK = 171	 # M2000 Reconfigurable RISC
        EM_CRAYNV2 = 172	 # Cray NV2 vector architecture
        EM_RX = 173  # Renesas RX
        EM_METAG = 174	 # Imagination Tech. META
        EM_MCST_ELBRUS = 175	 # MCST Elbrus
        EM_ECOG16 = 176	 # Cyan Technology eCOG16
        EM_CR16 = 177  # National Semi. CompactRISC CR16
        EM_ETPU = 178  # Freescale Extended Time Processing Unit
        EM_SLE9X = 179	 # Infineon Tech. SLE9X
        EM_L10M = 180  # Intel L10M
        EM_K10M = 181  # Intel K10M
        # reserved 182
        EM_AARCH64 = 183	 # ARM AARCH64
        # reserved 184
        EM_AVR32 = 185	 # Amtel 32-bit microprocessor
        EM_STM8 = 186  # STMicroelectronics STM8
        EM_TILE64 = 187	 # Tilera TILE64
        EM_TILEPRO = 188	 # Tilera TILEPro
        EM_MICROBLAZE = 189	 # Xilinx MicroBlaze
        EM_CUDA = 190  # NVIDIA CUDA
        EM_TILEGX = 191	 # Tilera TILE-Gx
        EM_CLOUDSHIELD = 192	 # CloudShield
        EM_COREA_1ST = 193	 # KIPO-KAIST Core-A 1st gen.
        EM_COREA_2ND = 194	 # KIPO-KAIST Core-A 2nd gen.
        EM_ARCV2 = 195	 # Synopsys ARCv2 ISA.
        EM_OPEN8 = 196	 # Open8 RISC
        EM_RL78 = 197  # Renesas RL78
        EM_VIDEOCORE5 = 198	 # Broadcom VideoCore V
        EM_78KOR = 199	 # Renesas 78KOR
        EM_56800EX = 200	 # Freescale 56800EX DSC
        EM_BA1 = 201  # Beyond BA1
        EM_BA2 = 202  # Beyond BA2
        EM_XCORE = 203	 # XMOS xCORE
        EM_MCHP_PIC = 204	 # Microchip 8-bit PIC(r)
        # reserved 205-209
        EM_KM32 = 210  # KM211 KM32
        EM_KMX32 = 211	 # KM211 KMX32
        EM_EMX16 = 212	 # KM211 KMX16
        EM_EMX8 = 213  # KM211 KMX8
        EM_KVARC = 214	 # KM211 KVARC
        EM_CDP = 215  # Paneve CDP
        EM_COGE = 216  # Cognitive Smart Memory Processor
        EM_COOL = 217  # Bluechip CoolEngine
        EM_NORC = 218  # Nanoradio Optimized RISC
        EM_CSR_KALIMBA = 219	 # CSR Kalimba
        EM_Z80 = 220  # Zilog Z80
        EM_VISIUM = 221	 # Controls and Data Services VISIUMcore
        EM_FT32 = 222  # FTDI Chip FT32
        EM_MOXIE = 223	 # Moxie processor
        EM_AMDGPU = 224	 # AMD GPU
        # reserved 225-242
        EM_RISCV = 243	 # RISC-V

        EM_BPF = 247  # Linux BPF -- in-kernel virtual machine
        EM_CSKY = 252      # C-SKY

        EM_NUM = 253

    class EV(Constant):
        # e_version
        EV_NONE = 0     # Invalid ELF version
        EV_CURRENT = 1  # Current version
        EV_NUM = 2


class Elf32_Shdr(BaseStructure):

    '''
    typedef struct
    {
    Elf32_Word	sh_name;		/* Section name (string tbl index) */
    Elf32_Word	sh_type;		/* Section type */
    Elf32_Word	sh_flags;		/* Section flags */
    Elf32_Addr	sh_addr;		/* Section virtual addr at execution */
    Elf32_Off	sh_offset;      /* Section file offset */
    Elf32_Word	sh_size;		/* Section size in bytes */
    Elf32_Word	sh_link;		/* Link to another section */
    Elf32_Word	sh_info;		/* Additional section information */
    Elf32_Word	sh_addralign;	/* Section alignment */
    Elf32_Word	sh_entsize;		/* Entry size if section holds table */
    } Elf32_Shdr;
    '''

    _fields_ = [
        ('sh_name', Elf32_Word),
        ('sh_type', Elf32_Word),
        ('sh_flags', Elf32_Word),
        ('sh_addr', Elf32_Addr),
        ('sh_offset', Elf32_Off),
        ('sh_size', Elf32_Word),
        ('sh_link', Elf32_Word),
        ('sh_info', Elf32_Word),
        ('sh_addralign', Elf32_Word),
        ('sh_entsize', Elf32_Word),
    ]

    class SHN(Constant):
        SHN_UNDEF = 0  # Undefined section
        SHN_LORESERVE = 0xff00  # Start of reserved indices
        SHN_LOPROC = 0xff00  # Start of processor-specific
        SHN_BEFORE = 0xff00  # Order section before all others (Solaris).
        SHN_AFTER = 0xff01  # Order section after all others (Solaris).
        SHN_HIPROC = 0xff1f  # End of processor-specific
        SHN_LOOS = 0xff20  # Start of OS-specific
        SHN_HIOS = 0xff3f  # End of OS-specific
        SHN_ABS = 0xfff1  # Associated symbol is absolute
        SHN_COMMON = 0xfff2  # Associated symbol is common
        SHN_XINDEX = 0xffff  # Index is in extra table.
        SHN_HIRESERVE = 0xffff  # End of reserved indices

        @classmethod
        def get_name(cls, value):
            name = super().get_name(value)
            if name == 'undefined':
                return value
            return name

    class SHT(Constant):
        SHT_NULL = 0  # Section header table entry unused
        SHT_PROGBITS = 1  # Program data
        SHT_SYMTAB = 2  # Symbol table
        SHT_STRTAB = 3  # String table
        SHT_RELA = 4  # Relocation entries with addends
        SHT_HASH = 5  # Symbol hash table
        SHT_DYNAMIC = 6  # Dynamic linking information
        SHT_NOTE = 7  # Notes
        SHT_NOBITS = 8  # Program space with no data (bss)
        SHT_REL = 9  # Relocation entries, no addends
        SHT_SHLIB = 10  # Reserved
        SHT_DYNSYM = 11  # Dynamic linker symbol table
        SHT_INIT_ARRAY = 14  # Array of constructors
        SHT_FINI_ARRAY = 15  # Array of destructors
        SHT_PREINIT_ARRAY = 16  # Array of pre-constructors
        SHT_GROUP = 17  # Section group
        SHT_SYMTAB_SHNDX = 18  # Extended section indices
        SHT_NUM = 19  # Number of defined types.
        SHT_LOOS = 0x60000000  # Start OS-specific.
        SHT_GNU_ATTRIBUTES = 0x6ffffff5  # Object attributes.
        SHT_GNU_HASH = 0x6ffffff6  # GNU-style hash table.
        SHT_GNU_LIBLIST = 0x6ffffff7  # Prelink library list
        SHT_CHECKSUM = 0x6ffffff8  # Checksum for DSO content.
        SHT_LOSUNW = 0x6ffffffa  # Sun-specific low bound.
        SHT_SUNW_move = 0x6ffffffa
        SHT_SUNW_COMDAT = 0x6ffffffb
        SHT_SUNW_syminfo = 0x6ffffffc
        SHT_GNU_verdef = 0x6ffffffd  # Version definition section.
        SHT_GNU_verneed = 0x6ffffffe  # Version needs section.
        SHT_GNU_versym = 0x6fffffff  # Version symbol table.
        SHT_HISUNW = 0x6fffffff  # Sun-specific high bound.
        SHT_HIOS = 0x6fffffff  # End OS-specific type
        SHT_LOPROC = 0x70000000  # Start of processor-specific
        SHT_HIPROC = 0x7fffffff  # End of processor-specific
        SHT_LOUSER = 0x80000000  # Start of application-specific
        SHT_HIUSER = 0x8fffffff  # End of application-specific

    class SHF(Constant):
        SHF_WRITE = (1 << 0)  # Writable
        SHF_ALLOC = (1 << 1)  # Occupies memory during execution
        SHF_EXECINSTR = (1 << 2)  # Executable
        SHF_MERGE = (1 << 4)  # Might be merged
        SHF_MASKPROC = 0xf0000000  # Processor-specific


class Elf32_Sym(BaseStructure):

    '''
    typedef struct
    {
    Elf32_Word	st_name;		/* Symbol name (string tbl index) */
    Elf32_Addr	st_value;		/* Symbol value */
    Elf32_Word	st_size;		/* Symbol size */
    unsigned char	st_info;		/* Symbol type and binding */
    unsigned char	st_other;		/* Symbol visibility */
    Elf32_Section	st_shndx;		/* Section index */
    } Elf32_Sym;
    '''

    _fields_ = [
        ('st_name', Elf32_Word),
        ('st_value', Elf32_Addr),
        ('st_size', Elf32_Word),
        ('st_info', u8),
        ('st_other', u8),
        ('st_shndx', Elf32_Half),
    ]

    class STB(Constant):
        STB_LOCAL = 0  # Local symbol
        STB_GLOBAL = 1  # Global symbol
        STB_WEAK = 2  # Weak symbol
        STB_NUM = 3  # Number of defined types.
        STB_LOOS = 10  # Start of OS-specific
        STB_GNU_UNIQUE = 10  # Unique symbol.
        STB_HIOS = 12  # End of OS-specific
        STB_LOPROC = 13  # Start of processor-specific
        STB_HIPROC = 15  # End of processor-specific

    class STT(Constant):
        STT_NOTYPE = 0  # Symbol type is unspecified
        STT_OBJECT = 1  # Symbol is a data object
        STT_FUNC = 2  # Symbol is a code object
        STT_SECTION = 3  # Symbol associated with a section
        STT_FILE = 4  # Symbol's name is file name
        STT_COMMON = 5  # Symbol is a common data object
        STT_TLS = 6  # Symbol is thread-local data object
        STT_NUM = 7  # Number of defined types.
        STT_LOOS = 10  # Start of OS-specific
        STT_GNU_IFUNC = 10  # Symbol is indirect code object
        STT_HIOS = 12  # End of OS-specific
        STT_LOPROC = 13  # Start of processor-specific
        STT_HIPROC = 15  # End of processor-specific


class Elf32_Rel(BaseStructure):

    '''
    typedef struct
    {
        Elf32_Addr	r_offset;		/* Address */
        Elf32_Word	r_info;			/* Relocation type and symbol index */
    } Elf32_Rel;
    '''

    _fields_ = [
        ('r_offset', Elf32_Addr),
        ('r_info', Elf32_Word),
    ]

    class R(Constant):
        R_386_NONE = 0  # No reloc
        R_386_32 = 1  # Direct 32 bit
        R_386_PC32 = 2  # PC relative 32 bit
        R_386_GOT32 = 3  # 32 bit GOT entry
        R_386_PLT32 = 4  # 32 bit PLT address
        R_386_COPY = 5  # Copy symbol at runtime
        R_386_GLOB_DAT = 6  # Create GOT entry
        R_386_JMP_SLOT = 7  # Create PLT entry
        R_386_RELATIVE = 8  # Adjust by program base
        R_386_GOTOFF = 9  # 32 bit offset to GOT
        R_386_GOTPC = 10  # 32 bit PC relative offset to GOT
        R_386_32PLT = 11  # R_386_TLS_TPOFF = 14 #  Offset in static TLS block
        R_386_TLS_IE = 15  # Address of GOT entry for static TLS block offset
        R_386_TLS_GOTIE = 16  # GOT entry for static TLS block offset
        R_386_TLS_LE = 17  # Offset relative to static TLS block
        R_386_TLS_GD = 18  # Direct 32 bit for GNU version of general dynamic thread local data
        R_386_TLS_LDM = 19  # Direct 32 bit for GNU version of local dynamic thread local data in LE code
        R_386_16 = 20
        R_386_PC16 = 21
        R_386_8 = 22
        R_386_PC8 = 23
        R_386_TLS_GD_32 = 24  # Direct 32 bit for general dynamic thread local data
        R_386_TLS_GD_PUSH = 25  # Tag for pushl in GD TLS code
        R_386_TLS_GD_CALL = 26  # Relocation for call to __tls_get_addr()
        R_386_TLS_GD_POP = 27  # Tag for popl in GD TLS code
        R_386_TLS_LDM_32 = 28  # Direct 32 bit for local dynamic thread local data in LE code
        R_386_TLS_LDM_PUSH = 29  # Tag for pushl in LDM TLS code
        R_386_TLS_LDM_CALL = 30  # Relocation for call to __tls_get_addr() in LDM code
        R_386_TLS_LDM_POP = 31  # Tag for popl in LDM TLS code
        R_386_TLS_LDO_32 = 32  # Offset relative to TLS block
        R_386_TLS_IE_32 = 33  # GOT entry for negated static TLS block offset
        R_386_TLS_LE_32 = 34  # Negated offset relative to static TLS block
        R_386_TLS_DTPMOD32 = 35  # ID of module containing symbol
        R_386_TLS_DTPOFF32 = 36  # Offset in TLS block
        R_386_TLS_TPOFF32 = 37  # Negated offset in static TLS block
        R_386_SIZE32 = 38  # 32-bit symbol size
        R_386_TLS_GOTDESC = 39  # GOT offset for TLS descriptor.
        R_386_TLS_DESC_CALL = 40  # Marker of call through TLS descriptor for relaxation.
        R_386_TLS_DESC = 41  # TLS descriptor containing pointer to code and to argument, returning the TLS offset for the symbol.
        R_386_IRELATIVE = 42  # Adjust indirectly by program base
        R_386_GOT32X = 43  # Load from 32 bit GOT entry, relaxable.
        # Keep this the last entry
        R_386_NUM = 44


class Elf32_Rela(Elf32_Rel):

    '''
    typedef struct
    {
        Elf32_Addr	r_offset;		/* Address */
        Elf32_Word	r_info;			/* Relocation type and symbol index */
        Elf32_Sword	r_addend;		/* Addend */
    } Elf32_Rela;
    '''

    _fields_ = [
        ('r_offset', Elf32_Addr),
        ('r_info', Elf32_Word),
        ('r_addend', Elf32_Sword),
    ]


class Elf32_Phdr(BaseStructure):

    '''
    typedef struct
    {
        Elf32_Word	p_type;			/* Segment type */
        Elf32_Off	p_offset;		/* Segment file offset */
        Elf32_Addr	p_vaddr;		/* Segment virtual address */
        Elf32_Addr	p_paddr;		/* Segment physical address */
        Elf32_Word	p_filesz;		/* Segment size in file */
        Elf32_Word	p_memsz;		/* Segment size in memory */
        Elf32_Word	p_flags;		/* Segment flags */
        Elf32_Word	p_align;		/* Segment alignment */
    } Elf32_Phdr;
    '''

    _fields_ = [
        ('p_type', Elf32_Word),
        ('p_offset', Elf32_Off),
        ('p_vaddr', Elf32_Addr),
        ('p_paddr', Elf32_Addr),
        ('p_filesz', Elf32_Word),
        ('p_memsz', Elf32_Word),
        ('p_flags', Elf32_Word),
        ('p_align', Elf32_Word),
    ]

    class PT(Constant):
        PT_NULL = 0  # Program header table entry unused
        PT_LOAD = 1  # Loadable program segment
        PT_DYNAMIC = 2  # Dynamic linking information
        PT_INTERP = 3  # Program interpreter
        PT_NOTE = 4  # Auxiliary information
        PT_SHLIB = 5  # Reserved
        PT_PHDR = 6  # Entry for header table itself
        PT_TLS = 7  # Thread-local storage segment
        PT_NUM = 8  # Number of defined types
        PT_LOOS = 0x60000000  # Start of OS-specific
        PT_GNU_EH_FRAME = 0x6474e550  # GCC .eh_frame_hdr segment
        PT_GNU_STACK = 0x6474e551  # Indicates stack executability
        PT_GNU_RELRO = 0x6474e552  # Read-only after relocation
        PT_GNU_PROPERTY = 0x6474e553  # GNU property
        PT_LOSUNW = 0x6ffffffa  # PT_SUNWBSS = 0x6ffffffa #  Sun Specific segment
        PT_SUNWSTACK = 0x6ffffffb  # Stack segment
        PT_HISUNW = 0x6fffffff  # PT_HIOS = 0x6fffffff #  End of OS-specific
        PT_LOPROC = 0x70000000  # Start of processor-specific
        PT_HIPROC = 0x7fffffff  # End of processor-specific

    class PF(Constant):
        PF_X = 1  # Segment is executable
        PF_W = 2  # Segment is writable
        PF_R = 4  # Segment is readable
        PF_MASKOS = 0x0ff00000  # OS-specific
        PF_MASKPROC = 0xf0000000  # Processor-specific


class Elf32_Dyn(Structure):
    '''
    typedef struct
    {
    Elf32_Sword	d_tag;			/* Dynamic entry type */
    union
        {
        Elf32_Word d_val;			/* Integer value */
        Elf32_Addr d_ptr;			/* Address value */
        } d_un;
    } Elf32_Dyn;
    '''

    class Dun(BaseUnion):

        _fields_ = [
            ('d_val', Elf32_Word),
            ('d_ptr', Elf32_Addr),
        ]

    _fields_ = [
        ('d_tag', Elf32_Sword),
        ('d_un', Dun),
    ]

    class DT(Constant):
        DT_NULL = 0  # Marks end of dynamic section
        DT_NEEDED = 1  # Name of needed library
        DT_PLTRELSZ = 2  # Size in bytes of PLT relocs
        DT_PLTGOT = 3  # Processor defined value
        DT_HASH = 4  # Address of symbol hash table
        DT_STRTAB = 5  # Address of string table
        DT_SYMTAB = 6  # Address of symbol table
        DT_RELA = 7  # Address of Rela relocs
        DT_RELASZ = 8  # Total size of Rela relocs
        DT_RELAENT = 9  # Size of one Rela reloc
        DT_STRSZ = 10  # Size of string table
        DT_SYMENT = 11  # Size of one symbol table entry
        DT_INIT = 12  # Address of init function
        DT_FINI = 13  # Address of termination function
        DT_SONAME = 14  # Name of shared object
        DT_RPATH = 15  # Library search path (deprecated)
        DT_SYMBOLIC = 16  # Start symbol search here
        DT_REL = 17  # Address of Rel relocs
        DT_RELSZ = 18  # Total size of Rel relocs
        DT_RELENT = 19  # Size of one Rel reloc
        DT_PLTREL = 20  # Type of reloc in PLT
        DT_DEBUG = 21  # For debugging; unspecified
        DT_TEXTREL = 22  # Reloc might modify .text
        DT_JMPREL = 23  # Address of PLT relocs
        DT_BIND_NOW = 24  # Process relocations of object
        DT_INIT_ARRAY = 25  # Array with addresses of init fct
        DT_FINI_ARRAY = 26  # Array with addresses of fini fct
        DT_INIT_ARRAYSZ = 27  # Size in bytes of DT_INIT_ARRAY
        DT_FINI_ARRAYSZ = 28  # Size in bytes of DT_FINI_ARRAY
        DT_RUNPATH = 29  # Library search path
        DT_FLAGS = 30  # Flags for the object being loaded
        DT_ENCODING = 32  # Start of encoded range
        DT_PREINIT_ARRAY = 32  # Array with addresses of preinit fct
        DT_PREINIT_ARRAYSZ = 33  # size in bytes of DT_PREINIT_ARRAY
        DT_SYMTAB_SHNDX = 34  # Address of SYMTAB_SHNDX section
        DT_NUM = 35  # Number used
        DT_LOOS = 0x6000000d  # Start of OS-specific
        DT_HIOS = 0x6ffff000  # End of OS-specific
        DT_LOPROC = 0x70000000  # Start of processor-specific
        DT_HIPROC = 0x7fffffff  # End of processor-specific
        DT_PROCNUM = 37  # Most used by any processor

        DT_VALRNGLO = 0x6ffffd00
        DT_GNU_PRELINKED = 0x6ffffdf5  # Prelinking timestamp
        DT_GNU_CONFLICTSZ = 0x6ffffdf6  # Size of conflict section
        DT_GNU_LIBLISTSZ = 0x6ffffdf7  # Size of library list
        DT_CHECKSUM = 0x6ffffdf8
        DT_PLTPADSZ = 0x6ffffdf9
        DT_MOVEENT = 0x6ffffdfa
        DT_MOVESZ = 0x6ffffdfb
        DT_FEATURE_1 = 0x6ffffdfc  # Feature selection (DTF_*).
        DT_POSFLAG_1 = 0x6ffffdfd  # Flags for DT_* entries, effecting 					   the following DT_* entry.
        DT_SYMINSZ = 0x6ffffdfe  # Size of syminfo table (in bytes)
        DT_SYMINENT = 0x6ffffdff  # Entry size of syminfo
        DT_VALRNGHI = 0x6ffffdff

        DT_ADDRRNGLO = 0x6ffffe00
        DT_GNU_HASH = 0x6ffffef5  # GNU-style hash table.
        DT_TLSDESC_PLT = 0x6ffffef6
        DT_TLSDESC_GOT = 0x6ffffef7
        DT_GNU_CONFLICT = 0x6ffffef8  # Start of conflict section
        DT_GNU_LIBLIST = 0x6ffffef9  # Library list
        DT_CONFIG = 0x6ffffefa  # Configuration information.
        DT_DEPAUDIT = 0x6ffffefb  # Dependency auditing.
        DT_AUDIT = 0x6ffffefc  # Object auditing.
        DT_PLTPAD = 0x6ffffefd  # PLT padding.
        DT_MOVETAB = 0x6ffffefe  # Move table.
        DT_SYMINFO = 0x6ffffeff  # Syminfo table.
        DT_ADDRRNGHI = 0x6ffffeff

        DT_VERSYM = 0x6ffffff0
        DT_RELACOUNT = 0x6ffffff9
        DT_RELCOUNT = 0x6ffffffa
        DT_FLAGS_1 = 0x6ffffffb  # State flags, see DF_1_* below.
        DT_VERDEF = 0x6ffffffc  # Address of version definition table
        DT_VERDEFNUM = 0x6ffffffd  # Number of version definitions
        DT_VERNEED = 0x6ffffffe  # Address of table with needed versions
        DT_VERNEEDNUM = 0x6fffffff  # Number of needed versions

        DT_AUXILIARY = 0x7ffffffd  # Shared object to load before self
        DT_FILTER = 0x7fffffff  # Shared object to get values from


class ElfTestCase(unittest.TestCase):

    def setUp(self) -> None:
        super().setUp()
        import os
        dirname = os.path.dirname(__file__)
        # filename = os.path.join(dirname, "../build/test.o")
        # filename = os.path.join(dirname, "../build/test")
        filename = os.path.join(dirname, "../build/test.so")
        self.file = open(filename, 'rb')
        self.shdrs = []

    def tearDown(self) -> None:
        self.file.close()
        super().tearDown()

    def read_header(self):
        data = self.file.read(sizeof(Elf32_Ehdr))
        # logger.debug(data)
        header = Elf32_Ehdr.from_buffer_copy(data)
        self.header = header

    def print_header(self):
        header = self.header
        logger.info("elf magic %s", header.e_ident.ei_magic.to_bytes(4, byteorder='little'))
        logger.info("elf class %s", ElfIdent.CLASS.get_name(header.e_ident.ei_class))
        logger.info("elf data %s", ElfIdent.DATA.get_name(header.e_ident.ei_data))

        self.splitter()

        logger.info("elf type --> %s", Elf32_Ehdr.ET.get_name(header.e_type))
        logger.info("elf machine --> %s", Elf32_Ehdr.EM.get_name(header.e_machine))
        logger.info("elf version --> %s", Elf32_Ehdr.EV.get_name(header.e_version))

        for name, _ in Elf32_Ehdr._fields_:
            if name in {"e_type", "e_machine", "e_version", 'e_ident'}:
                continue
            logger.info(f"elf {name} --> 0x{getattr(header, name):x}")

        self.splitter()

    def read_shdrs(self):
        self.shdrs = []

        file = self.file
        header = self.header

        file.seek(header.e_shoff)

        for _ in range(header.e_shnum):
            data = file.read(header.e_shentsize)
            shdr = Elf32_Shdr.from_buffer_copy(data)
            self.shdrs.append(shdr)

            # for name, _ in Elf32_Shdr._fields_:
            #     logger.info("%s --> %s", name, getattr(shdr, name))

            # self.splitter(1)

        for shdr in self.shdrs:
            if shdr.sh_size == 0:
                shdr.data = None
            else:
                file.seek(shdr.sh_offset)
                shdr.data = file.read(shdr.sh_size)

    def get_str(self, data: bytes, index) -> str:
        end = data.find(b'\0', index)
        if end == -1:
            return ''
        string = data[index:end]
        return string.decode("utf8")

    def print_shdrs(self):
        strtab = self.shdrs[self.header.e_shstrndx]
        data = strtab.data
        for index, shdr in enumerate(self.shdrs):
            logger.info(f'section index {index}')
            logger.info(f'section name {self.get_str(data, shdr.sh_name)}')
            logger.info(f'section type {Elf32_Shdr.SHT.get_name(shdr.sh_type)}')
            flags = set([shdr.sh_flags & (1 << var) for var in range(32)])
            logger.info(f'section flags {[Elf32_Shdr.SHF.get_name(flag) for flag in flags if flag ]}')
            logger.info(f'section addr 0x{shdr.sh_addr:X}')
            # logger.info(f'section offset 0x{shdr.sh_offset:X}')
            # logger.info(f'section size 0x{shdr.sh_size:X}')
            logger.info(f'section link 0x{shdr.sh_link:X}')
            logger.info(f'section info 0x{shdr.sh_info:X}')
            # logger.info(f'section align {shdr.sh_addralign}')
            # logger.info(f'section esize {shdr.sh_entsize}')

            self.splitter(1)
        self.splitter()

    def splitter(self, indent=0):
        start = indent * 4
        logger.info(f"{' ' * start}{'-' * (50 - start)}")

    def get_st_bind(self, info):

        return info >> 4

    def get_st_type(self, info):

        return info & 0xf

    def get_st_info(self, bind, type):

        return (bind << 4) | (type & 0xf)

    def print_struct(self, instance: BaseStructure):
        cls = type(instance)
        for name, _ in cls._fields_:
            value = getattr(instance, name)
            if isinstance(value, int):
                content = f"0x{value:x}"
            else:
                content = value
            logger.info(f"{cls.__name__} {name} --> {content}")

    def read_symbols(self):
        shdrs = self.shdrs
        for shdr in self.shdrs:
            if shdr.sh_type != Elf32_Shdr.SHT.SHT_SYMTAB:
                continue

            stream = BytesIO(shdr.data)
            stream.seek(0)

            strtab = self.shdrs[shdr.sh_link]
            data = strtab.data

            self.symtab = []
            while True:
                buf = stream.read(shdr.sh_entsize)
                if not buf:
                    break
                sym = Elf32_Sym.from_buffer_copy(buf)
                sym.name = self.get_str(data, sym.st_name)
                self.symtab.append(sym)

    def print_symbols(self):
        for sym in self.symtab:

            logger.info("symbol name %s", sym.name)
            logger.info(f"symbol value 0x{sym.st_value:x}")
            logger.info(f"symbol size 0x{sym.st_size:x}")
            logger.info(f"symbol shndx {Elf32_Shdr.SHN.get_name(sym.st_shndx)}")
            logger.info("symbol bind %s", Elf32_Sym.STB.get_name(self.get_st_bind(sym.st_info)))
            logger.info("symbol type %s", Elf32_Sym.STT.get_name(self.get_st_type(sym.st_info)))

            self.splitter(1)
        self.splitter()

    def get_r_sym(self, info):

        return info >> 8

    def get_r_type(self, info):

        return info & 0xff

    def get_r_info(self, sym, type):

        return (sym << 8) | type

    def read_rel(self):
        self.reltab = []

        types = {
            Elf32_Shdr.SHT.SHT_REL: Elf32_Rel,
            Elf32_Shdr.SHT.SHT_RELA: Elf32_Rela,
        }

        for shdr in self.shdrs:
            if shdr.sh_type not in types:
                continue

            stream = BytesIO(shdr.data)
            stream.seek(0)

            cls = types[shdr.sh_type]

            while True:
                data = stream.read(sizeof(cls))
                if not data:
                    break
                rel = cls.from_buffer_copy(data)
                self.reltab.append(rel)

    def print_rel(self):
        for rel in self.reltab:
            cls = type(rel)
            logger.info(f"rel offset 0x{rel.r_offset:x}")
            logger.info("rel sym %s", self.get_r_sym(rel.r_info))
            logger.info("rel type %s", cls.R.get_name(self.get_r_type(rel.r_info)))
            if isinstance(cls, Elf32_Rela):
                logger.info(f"rel addend 0x{rel.r_addend:x}")

            self.splitter(1)
        self.splitter()

    def read_phdrs(self):
        self.phdrs = []
        file = self.file
        header = self.header

        file.seek(header.e_phoff)

        for _ in range(header.e_phnum):
            data = file.read(header.e_phentsize)
            phdr = Elf32_Phdr.from_buffer_copy(data)
            self.phdrs.append(phdr)

        for phdr in self.phdrs:
            if phdr.p_filesz == 0:
                phdr.data = None
            else:
                file.seek(phdr.p_offset)
                phdr.data = file.read(phdr.p_filesz)

    def print_phdrs(self):
        for phdr in self.phdrs:
            logger.info(f"phdr type --> {Elf32_Phdr.PT.get_name(phdr.p_type)}")
            logger.info(f"phdr offset --> 0x{phdr.p_offset:x}")
            logger.info(f"phdr vaddr --> 0x{phdr.p_vaddr:x}")
            logger.info(f"phdr paddr --> 0x{phdr.p_paddr:x}")
            logger.info(f"phdr filesz --> 0x{phdr.p_filesz:x}")
            logger.info(f"phdr memsz --> 0x{phdr.p_memsz:x}")
            flags = set([phdr.p_flags & (1 << var) for var in range(32)])
            logger.info(f'phdr flags --> {[Elf32_Phdr.PF.get_name(flag) for flag in flags if flag ]}')
            logger.info(f"phdr align --> 0x{phdr.p_align:x}")
            # logger.info(f"phdr data --> {phdr.data}")
            self.splitter(1)
        self.splitter()

    def read_dyns(self):
        self.dyns = []

        for phdr in self.phdrs:
            if phdr.p_type != Elf32_Phdr.PT.PT_DYNAMIC:
                continue
            # logger.debug(phdr.data)

            stream = BytesIO(phdr.data)
            stream.seek(0)

            while True:
                data = stream.read(sizeof(Elf32_Dyn))
                if not data:
                    break
                dyn = Elf32_Dyn.from_buffer_copy(data)
                self.dyns.append(dyn)

        # 经测试 .dynamic section 与 PT_DYNAMIC 的内容完全相同

        # for shdr in self.shdrs:
        #     if shdr.sh_type != Elf32_Shdr.SHT.SHT_DYNAMIC:
        #         continue
        #     logger.debug(shdr.data)

    def print_dyns(self):

        for dyn in self.dyns:
            logger.info(f'dyn tag --> {Elf32_Dyn.DT.get_name(dyn.d_tag)}')
            logger.info(f'dyn val 0x{dyn.d_un.d_val:x}')
            # logger.info(f'dyn ptr 0x{dyn.d_un.d_ptr:x}')
            self.splitter(1)
        self.splitter()

    def elf_hash(self, name: bytes):
        h = 0
        g = 0

        index = 0
        while len(name) < index and name[index]:
            h = (h << 4) + name[index]
            if g == (h & 0xf0000000):
                h ^= g >> 24
            h &= ~g
            index += 1
        return h

    def read_got(self):
        pass

    def test(self):

        self.splitter()
        self.read_header()
        # self.print_header()

        self.read_shdrs()
        # self.print_shdrs()

        self.read_symbols()
        # self.print_symbols()

        self.read_rel()
        self.print_rel()

        self.read_phdrs()
        # self.print_phdrs()

        self.read_dyns()
        # self.print_dyns()

        self.read_got()


if __name__ == '__main__':
    unittest.main()
