from unicorn import *
from unicorn.arm_const import *
from unicornafl import *
import subprocess
import logging
import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)

#######################################
# Binary Loading
#######################################

STACK_ADDR = 0x40000000
STACK_SIZE = 0x10000
PAGE_SIZE = 0x1000

def load_elf(uc, elf_path):
    with open(elf_path, 'rb') as f:
        elffile = ELFFile(f)
        for seg in elffile.iter_segments():
            if seg['p_type'] != 'PT_LOAD':
                continue
            vaddr = seg['p_vaddr']
            memsz = seg['p_memsz']
            filesz = seg['p_filesz']
            offset = seg['p_offset']
            aligned_vaddr = vaddr & ~(PAGE_SIZE - 1)
            offset_in_page = vaddr - aligned_vaddr
            aligned_size = ((offset_in_page + memsz + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE
            try:
                uc.mem_map(aligned_vaddr, aligned_size)
                logging.debug("Mapped segment: addr=0x%08x size=0x%x perms=%d"%(aligned_vaddr, aligned_size, UC_PROT_ALL))
            except Exception as e:
                logging.debug("Failed mapping at 0x%08x: %s"%(aligned_vaddr, e))
            uc.mem_write(vaddr, seg.data())
            
def get_symbol_addr(elf_path, symbol):
    addr = int(subprocess.Popen(f'nm --print-size ./vulnerable-arm | grep -E " {symbol}$" | cut -d " " -f 1', shell=True, stdout=subprocess.PIPE).stdout.read(), 16)
    size = int(subprocess.Popen(f'nm --print-size ./vulnerable-arm | grep -E " {symbol}$" | cut -d " " -f 2', shell=True, stdout=subprocess.PIPE).stdout.read(), 16)
    logging.debug(f"symbol {symbol} is at address 0x{addr:0x} length {size} ")
    return (addr, size)

def get_return_addr(elf_path, symbol):
    addr = int(subprocess.Popen(f'arm-linux-gnueabihf-objdump --disassemble={symbol} ./vulnerable-arm | grep -E "pop.*pc" | cut -f 1 | sed s/://', shell=True, stdout=subprocess.PIPE).stdout.read(), 16)
    logging.debug(f"symbol {symbol} return at address 0x{addr:0x}")
    return addr

def hook_code(uc, address, size, user_data):
    logging.debug("Executing @ 0x%08x (size=%d)"%(address, size))

# callback for tracing invalid memory access (READ or WRITE)
def hook_mem_invalid(uc, access, address, size, value, user_data):
    logging.debug(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
              % (address, size, value))
    return False

# callback for tracing memory access (READ or WRITE)
def hook_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        logging.debug(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
              % (address, size, value))
    else:  # READ
        logging.debug(">>> Memory is being READ at 0x%x, data size = %u" \
              % (address, size))

def hook_bypass(uc, address, size, user_data):
    logging.debug(f"[X] Bypass function at address 0x{address:0x}")
    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

def main():
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    elf_path = sys.argv[2]
    ####################
    #### INIT   #####
    ####################

    # trace all instructions executed
    uc.hook_add(UC_HOOK_CODE, hook_code)
    # intercept invalid memory events
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
    # tracing all memory READ & WRITE access
    uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access)

    # Load binary code
    load_elf(uc, elf_path)

    # Map stack
    uc.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    uc.reg_write(UC_ARM_REG_SP, STACK_ADDR+STACK_SIZE)
    
    # Set entry point
    main_addr, main_size = get_symbol_addr(elf_path, "main")
    buffer_addr, buffer_size = get_symbol_addr(elf_path, "buf")

    logging.debug("entrypoint_addr : 0x%x"%main_addr)
    uc.reg_write(UC_ARM_REG_PC, main_addr)

    # Set endpoint
    endpoints = [get_return_addr(elf_path, "main")]
    logging.debug("endpoint : 0x%x"%endpoints[0])

    # Hook libc functions
    memset_addr, memset_size = get_symbol_addr(elf_path, "memset")
    logging.debug(f"Hook memset @0x{memset_addr:0x}")
    uc.hook_add(UC_HOOK_CODE, hook_bypass, begin=memset_addr-2,end=memset_addr+2)

    read_addr, read_size = get_symbol_addr(elf_path, "read")
    logging.debug(f"Hook read @0x{read_addr:0x}")
    uc.hook_add(UC_HOOK_CODE, hook_bypass, begin=read_addr-2,end=read_addr+2)

    read_addr, read_size = get_symbol_addr(elf_path, "puts")
    logging.debug(f"Hook puts @0x{read_addr:0x}")
    uc.hook_add(UC_HOOK_CODE, hook_bypass, begin=read_addr-2,end=read_addr+2)


    ####################
    #### FUZZING   #####
    ####################

    # -----------------------------------------------------
    # FUZZING CALLBACK - Executed at each fuzzing round
    # -----------------------------------------------------
    def place_input_callback(uc, input, persistent_round, data):
        logging.debug("Entering afl-unicorn callback")
        afl_input = input.raw
        if len(afl_input) > buffer_size:
            return False

        uc.mem_write(buffer_addr, afl_input)
        logging.debug("Exit callback")

    # Start the fuzzer.
    logging.debug("start fuzz")
    uc_afl_fuzz(uc=uc, input_file=sys.argv[1], place_input_callback=place_input_callback, exits=endpoints, persistent_iters=10000)

if __name__ == '__main__':
      main()