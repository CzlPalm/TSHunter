#!/usr/bin/env python3
"""
快速验证 BoringSSL 中"label 字符串 → 下一条 CALL → derive_secret"模式是否成立。
不依赖 Ghidra，直接静态扫描二进制。
"""
import sys
from collections import Counter
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_IMM

LABELS = [b"c hs traffic", b"s hs traffic", b"c ap traffic", b"s ap traffic"]
GROUND_TRUTH_HKDF_RVA = 0x048837E0
GROUND_TRUTH_WRAPPER_RVA = 0x04EE8210

def find_string_addrs(binary, needle_bytes):
    """在所有只读段里找 needle\\x00 的所有出现位置（绝对 VA）。"""
    needle = needle_bytes + b"\x00"
    out = []
    for sec in binary.sections:
        if sec.name not in (".rodata", ".rdata", ".data.rel.ro"):
            continue
        data = bytes(sec.content)
        i = 0
        while True:
            j = data.find(needle, i)
            if j < 0:
                break
            out.append(sec.virtual_address + j)
            i = j + 1
    return out

def find_lea_refs(text_section, target_va):
    """在 .text 里枚举所有 lea reg, [rip+disp] 指令，返回那些 disp 解析到 target_va 的指令地址。"""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    code = bytes(text_section.content)
    base = text_section.virtual_address
    refs = []
    for ins in md.disasm(code, base):
        if ins.mnemonic != "lea":
            continue
        for op in ins.operands:
            if op.type == CS_OP_MEM and op.mem.base in (41,):  # X86_REG_RIP = 41
                target = ins.address + ins.size + op.mem.disp
                if target == target_va:
                    refs.append(ins.address)
                    break
    return refs

def find_next_direct_call(text_section, start_va, max_bytes=8192):
    """从 start_va 开始线性反汇编，返回遇到的第一条直接 CALL 的 (call_va, target_va)。
    遇到 RET 提前结束。"""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    base = text_section.virtual_address
    off = start_va - base
    if off < 0 or off >= len(text_section.content):
        return None, None
    code = bytes(text_section.content)[off:off + max_bytes]
    for ins in md.disasm(code, start_va):
        if ins.mnemonic == "call":
            md2 = Cs(CS_ARCH_X86, CS_MODE_64)
            md2.detail = True
            d = next(md2.disasm(ins.bytes, ins.address))
            for op in d.operands:
                if op.type == CS_OP_IMM:
                    return ins.address, op.imm
            return ins.address, None  # indirect
        if ins.mnemonic == "ret":
            return None, None
    return None, None

def main(path):
    print(f"[*] 解析: {path}")
    binary = lief.parse(path)
    image_base = binary.imagebase
    text = next(s for s in binary.sections if s.name == ".text")
    print(f"[*] image_base = 0x{image_base:X}, .text VA = 0x{text.virtual_address:X}, size = 0x{len(text.content):X}")
    print(f"[*] Ground truth (manual): HKDF derive_secret RVA = 0x{GROUND_TRUTH_HKDF_RVA:08X}")
    print(f"[*] Ground truth (manual): wrapper             RVA = 0x{GROUND_TRUTH_WRAPPER_RVA:08X}")
    print()

    vote_counter = Counter()
    detail_rows = []

    for label in LABELS:
        addrs = find_string_addrs(binary, label)
        print(f"=== label \"{label.decode()}\" ===")
        if not addrs:
            print(f"  [WARN] 字符串未找到")
            continue
        for saddr in addrs:
            print(f"  string @ 0x{saddr:08X} (RVA 0x{saddr - image_base:08X})")
            refs = find_lea_refs(text, saddr)
            if not refs:
                print(f"    (没有 LEA RIP-rel 指令引用)")
                continue
            for ref in refs:
                call_va, target = find_next_direct_call(text, ref)
                if target is None:
                    print(f"    LEA @ 0x{ref:08X}  →  next CALL: NONE/INDIRECT")
                    continue
                rva = target - image_base
                print(f"    LEA @ 0x{ref:08X}  →  CALL @ 0x{call_va:08X}  →  target 0x{target:08X} (RVA 0x{rva:08X})")
                vote_counter[rva] += 1
                detail_rows.append((label.decode(), saddr, ref, call_va, rva))
        print()

    print("=" * 60)
    print("[*] next-CALL 投票结果（rva → 票数）：")
    for rva, n in vote_counter.most_common():
        marker = ""
        if rva == GROUND_TRUTH_HKDF_RVA:
            marker = "  ✅ MATCHES GROUND TRUTH derive_secret"
        elif rva == GROUND_TRUTH_WRAPPER_RVA:
            marker = "  ❌ wrapper (wrong)"
        print(f"  RVA 0x{rva:08X}  votes={n}{marker}")

    if vote_counter:
        winner_rva, winner_votes = vote_counter.most_common(1)[0]
        print()
        if winner_rva == GROUND_TRUTH_HKDF_RVA:
            print(f"[PASS] next-CALL 投票策略可行：胜出 0x{winner_rva:08X} ({winner_votes} 票) = ground truth")
        else:
            print(f"[FAIL] 胜出 0x{winner_rva:08X} ({winner_votes} 票) ≠ ground truth 0x{GROUND_TRUTH_HKDF_RVA:08X}")
            print(f"       需要重新设计策略，请把上面完整输出贴出来。")
    else:
        print("[FAIL] 没有任何投票，整个机制不适用。")

if __name__ == "__main__":
    main(sys.argv[1])
