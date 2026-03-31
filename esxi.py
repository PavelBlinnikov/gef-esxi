from gef import *
import threading
from vmx_constants import *

@register_command
class ESXi(GenericCommand):
    _cmdline_ = "esxi"
    _category_ = "99. GEF Maintenance Command"
    _aliases_ = ["esx"]
    __doc__ = ""

    parser = argparse.ArgumentParser(prog=_cmdline_)
    subparsers = parser.add_subparsers(
        dest="func",
        required=True,
        help="available functions (use --help after command for more info)",
    )

    p_regs = subparsers.add_parser('regs', help='print userspace registers on syscall enter')

    p_base = subparsers.add_parser('base', help='print ESX base')

    p_vmk_load = subparsers.add_parser('vmk-file', help='load vmk binary')
    p_vmk_load.add_argument("vmk_path", help="filepath to vmk binary")

    p_vmx_load = subparsers.add_parser('vmx-file', help='load vmx binary')
    p_vmx_load.add_argument("vmx_path", help="filepath to vmx binary")
    
    p_mods = subparsers.add_parser('mods', help='load vmm mods')
    
    p_vmexit = subparsers.add_parser('vmexit', help='trace vm-exits')
    p_vmexit.add_argument('on_off', help='')

    _syntax_ = parser.format_help()

    _example_ = "..."
    _note_ = "..."

    class SetFunctionOnBreak(gdb.Breakpoint):
        def __init__(self, spec, function):
            super().__init__(spec, 
                             type=gdb.BP_HARDWARE_BREAKPOINT,
                             internal=True,
                             temporary=True)
            self.handler_function = function

        def _is_safe_event_thread(self):
            try:
                gdb.newest_frame()
            except gdb.error as e:
                if "Selected thread is running" in str(e) or 'Cannot execute this command while the target is running' in str(e):
                    return False
            return True

        def stop(self):
            return self.handler_function()

    class Section:
        size = 0
        lma = 0
        file_off = 0

        def __init__(self, size, lma, file_off):
            self.size = int(size, 16)
            self.lma = int(lma, 16)
            self.file_off = int(file_off, 16)

    def __init__(self):
        self.vmk_base = 0
        self.vmk_path = ""
        self.vmx_path = ""
        self.monitor_addr_text = 0
        self.monitor_addr_data = 0
        self.mods = {}
        self.mods_resolved = False

        super().__init__(complete=gdb.COMPLETE_FILENAME)
        return

    def read_msr(self, msr_num):
        pc = get_register("$pc")
        cur_data = read_int32_from_memory(pc-2)

        if cur_data == 0xc390f4fb: # sti; hlt; nop; ret
            gdb.execute("si")

        return MsrCommand.read_msr(msr_num)

    def print_regs(self):
        msr_gs = self.read_msr(0xc000_0101) # MSR_GS_BASE
        if msr_gs == 0:
            self.quiet_info("MSG_GS_BASE is 0")
            return

        self.quiet_info("MSR_GS_BASE is {:x}".format(msr_gs))
        stack_addr = read_int64_from_memory(msr_gs + 0x4c0) - 0xc0
        if stack_addr == -0xc0:
            self.quiet_err("stack_addr is empty")
            return
        self.quiet_info("stack addr is {:x}".format(stack_addr))

        regs_list = {
                    "rsp": stack_addr+0xb0,
                    "r11": stack_addr+0xa8,
                    "rcx": stack_addr+0x98,
                    "rdx": stack_addr+0x28,
                    "rbx": stack_addr+0x30,
                    "rbp": stack_addr+0x38,
                    "rsi": stack_addr+0x40,
                    "rdi": stack_addr+0x48,
                    "r8 ": stack_addr+0x50,
                    "r9 ": stack_addr+0x58,
                    "r10": stack_addr+0x60,
                    "r10": stack_addr+0x68,
                    "r12": stack_addr+0x70,
                    "r13": stack_addr+0x78,
                    "r14": stack_addr+0x80,
                    "r15": stack_addr+0x88,
        }

        gef_print(titlify("ESXi userspace registers"))
        for reg in regs_list:
            gef_print("${:4s}: {:#018x}".format(reg, read_int64_from_memory(regs_list[reg])))

    def find_base(self):
        prev_pc = get_register("$pc")
        cur_data = read_int32_from_memory(prev_pc-2)
        prev_pc_high = prev_pc >> 32

        if cur_data == 0xc390f4fb: # sti; hlt; nop; ret;
            esx_base = prev_pc
        else:
            esx_base = self.read_msr(0xc000_0082) # MSR_LSTAR
            if esx_base == 0:
                self.quiet_err("MSR_LSTAR is 0")
                return

            cur_pc_high = get_register("$pc") >> 32

            if (cur_pc_high != prev_pc_high or prev_pc_high != (esx_base >> 32)): # sti; hlt; nop; ret;
                self.quiet_warn("unstable situation, try again")
                return False

        #self.quiet_info("MSR_LSTAR is {:x}".format(esx_base))

        while True:
            try:
                data = read_int8_from_memory(esx_base)
                esx_base -= 0x1000
            except gdb.MemoryError:
                break

        while True:
            try:
                data = read_int8_from_memory(esx_base)
                break
            except gdb.MemoryError:
                esx_base += 1
        
        self.quiet_info("VMKernel .text: {:x}".format(esx_base))
        self.vmk_base = esx_base
        return esx_base

    def load_vmk_file(self, path):
        if self.vmk_base == 0:
            base = self.find_base()
            if base == False or base is None:
                return

        if not os.path.exists(path):
            self.quiet_err(f"{path} doesn't exist")
            return

        vmk_sections = self.get_sections(path)

        gdb_command = f"add-symbol-file {path} "
        for sect in vmk_sections:
            if vmk_sections[sect].lma == 0:
                continue
            offset = vmk_sections[sect].lma - vmk_sections[".text"].lma
            gdb_command += f"-s {sect} {self.vmk_base + offset} "

        gdb.execute(gdb_command)
        self.vmk_path = path

        gdb.execute("context")

    def load_vmx_file(self, path):
        if not os.path.exists(path):
            self.quiet_err(f"{path} doesn't exist")
            return
        data = subprocess.check_output(["objdump", "-h", path]).decode("utf-8")
        if 'vmmblob' in data:
            self.quiet_info("vmx path successfully set")
            self.vmx_path = path
        else:
            self.quiet_err("vmmblob is not found in vmx")

    def vmexit_handler(self):
        # just a lil hack for now, will replace with offset to .shared_per_vmx_vcpu later
        vc_base = int(str(Disasm.gef_instruction_n(gdb.parse_and_eval("HVExitLowLevel"), 0)).split('#')[-1].strip(), 16) - 0x20
        gef_print(f"__VC base is {hex(vc_base)}")
        guest_rip = read_int64_from_memory(vc_base+0x18)
        guest_rsp = read_int64_from_memory(vc_base+0x40)

        vm_exit_reason = vmx_exit_reason[get_register('$rdi')]
        gef_print(f"VMCS_EXIT_REASON: VMX_EXIT_REASON_{vm_exit_reason}")
        gef_print(f"VMCS_GUEST_RIP: {hex(guest_rip)}")
        gef_print(f"VMCS_GUEST_RSP: {hex(guest_rsp)}")

    def vmexit_setup(self, on_off):
        if not self.mods_resolved:
            self.quiet_err("execute `esx vmx-file` and `esx mods` first")
            return

        if on_off == "on":
            self.hvexit_bp = self.SetFunctionOnBreak("HVExit", self.vmexit_handler)
        elif on_off == "off":
            try:
                self.hvexit_bp.enabled = False
            except:
                pass

    def get_sections(self, path):
        data = subprocess.check_output(["objdump", "-h", path]).decode('utf-8').split('\n')
        data = list(filter(lambda i: len(i) > 1 and i.strip()[0].isdigit(), data))

        return {line.split()[1]: self.Section(line.split()[2], line.split()[4], line.split()[-2]) for line in data}

    def load_sec_mods(self):
        if gdb.selected_frame().name() != "Monitor_Init":
            self.quiet_err("break on Monitor_Init first")
            return

        if self.monitor_addr_text == 0:
            self.quiet_err("execute `esx mods` first")
            return

        try:
            monConfig = int(gdb.parse_and_eval('monConfig').address)
        except gdb.error:
            self.quiet_err("monConfig is not found")
            return

        mods = []
        cur_addr = monConfig
        while True:
            mod_name = read_cstring_from_memory(cur_addr, max_length=20)
            if mod_name == "":
                break
            mods.append(mod_name)
            cur_addr += 20

        maps = {}
        # map .text sections
        cur_addr = self.monitor_addr_text
        for fname in mods:
            fname = f"/tmp/vmmmods_dumped/{fname}.vmm"
            text_sect = self.get_sections(fname)[".text"]

            maps[fname] = f"-s .text {cur_addr} "

            cur_addr = (cur_addr + text_sect.size + 15) & ~15

        cur_addr = (cur_addr + 4095) & ~4095
        for fname in mods:
            fname = f"/tmp/vmmmods_dumped/{fname}.vmm"
            rodata_sect = self.get_sections(fname).get(".rodata")
            if rodata_sect == None:
                continue

            maps[fname] += f"-s .rodata {cur_addr} "
            
            cur_addr = (cur_addr + rodata_sect.size + 15) & ~15

        cur_addr = self.monitor_addr_data
        for fname in mods:
            fname = f"/tmp/vmmmods_dumped/{fname}.vmm"
            data_sect = self.get_sections(fname).get(".data")
            if data_sect == None:
                continue

            maps[fname] += f"-s .data {cur_addr}"
            
            cur_addr = (cur_addr + data_sect.size + 31) & ~31

        for fname in maps:
            gdb.execute(f"add-symbol-file {fname} {maps[fname]}")

        self.mods_resolved = True

    def load_base_mods(self):
        if self.vmx_path == "":
            self.quiet_err("Load vmx file with `esx vmx-file` first")
            return

        # here we try to avoid using third-party libs such as pyelftools

        # objcopy ./vmx --dump-section vmmblob=vmmblob.bin
        data = subprocess.check_output(["objcopy", self.vmx_path, "--dump-section", "vmmblob=/tmp/vmmblob.bin"]).decode('utf-8')
        if data != "":
            self.quiet_err(f"vmmblob objcopy failed: {data}")
            return

        vmmblob_sections = self.get_sections("/tmp/vmmblob.bin")

        gdb_command = f"add-symbol-file /tmp/vmmblob.bin "
        vmmblob_entry = vmmblob_sections[".text"].lma
        for sect in vmmblob_sections:
            if vmmblob_sections[sect].lma == 0:
                continue
            gdb_command += f"-s {sect} {vmmblob_sections[sect].lma} "

        self.quiet_info("vmmblob entrypoint is {:#x}".format(vmmblob_entry))
        gdb.execute(gdb_command)

        data = subprocess.check_output(["objcopy", "/tmp/vmmblob.bin", "--dump-section", "vmmmods=/tmp/vmmmods.bin"]).decode('utf-8')
        if data != "":
            self.quiet_err(f"vmmmods objcopy failed: {data}")
            return

        self.mods = self.get_sections("/tmp/vmmmods.bin")

        os.makedirs("/tmp/vmmmods_dumped", exist_ok=True)

        for module in self.mods:
            data = subprocess.check_output(["objcopy", "/tmp/vmmmods.bin", "--dump-section", 
                                            f"{module}=/tmp/vmmmods_dumped/{module}"]).decode('utf-8')
            if data != "":
                self.quiet_err(f"{module} objcopy failed: {data}")
                return

        data = subprocess.check_output(["objdump", "-t", "/tmp/vmmmods_dumped/vmm.vmm"]).decode('utf-8')

        if 'MONITOR_READONLY_REGION_VA' not in data:
            self.quiet_err("vmm base is not found")
            return

        self.monitor_addr_text = int(data.split('MONITOR_READONLY_REGION_VA')[0].split('\n')[-1].split()[0], 16)
        self.monitor_addr_data = int(data.split('MONITOR_DATA_VA')[0].split('\n')[-1].split()[0], 16)

        gdb.execute(f"add-symbol-file /tmp/vmmmods_dumped/vmm.vmm -s .text {hex(self.monitor_addr_text)} -s .data {hex(self.monitor_addr_data)}")
        self.quiet_info("base mods loaded, now start the vm to load the rest")

        self.SetFunctionOnBreak("Monitor_Init", self.load_sec_mods)

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        match args.func:
            case "regs":
                self.print_regs()
            case "base":
                self.find_base()
            case "vmk-file":
                self.load_vmk_file(args.vmk_path)
            case "vmx-file":
                self.load_vmx_file(args.vmx_path)
            case "mods":
                self.load_base_mods()
            case "vmexit":
                self.vmexit_setup(args.on_off)
        return

