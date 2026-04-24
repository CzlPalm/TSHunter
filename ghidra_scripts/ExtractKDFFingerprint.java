// ExtractKDFFingerprint.java
// 使用方法：光标放在目标函数（FUN_0a32d4b0）内任意位置，运行脚本
// 输出：函数入口地址(RVA) + 指纹字节序列（与 TLSKeyHunter 格式兼容）

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class ExtractKDFFingerprint extends GhidraScript {

    // 最小指纹长度（字节），与 TLSKeyHunter 论文一致
    private static final int MIN_FINGERPRINT_BYTES = 32;

    @Override
    public void run() throws Exception {

        // 1. 获取当前光标所在函数
        Function func = getFunctionContaining(currentAddress);
        if (func == null) {
            printerr("[-] 未找到函数，请将光标放在目标函数内部后重新运行");
            return;
        }

        Address entryPoint = func.getEntryPoint();
        println("[*] 函数名称 : " + func.getName());
        println("[*] 函数入口 : " + entryPoint);

        // 2. 计算 RVA（减去程序镜像基址）
        long imageBase = currentProgram.getImageBase().getOffset();
        long rva = entryPoint.getOffset() - imageBase;
        println("[*] RVA (基址已减) : 0x" + Long.toHexString(rva).toUpperCase());

        // 3. 从函数入口开始遍历指令，提取字节指纹
        InstructionIterator instrIter = currentProgram.getListing()
                .getInstructions(entryPoint, true);

        StringBuilder hexBuilder = new StringBuilder();
        int totalBytes = 0;
        boolean done = false;

        while (instrIter.hasNext() && !done) {
            Instruction instr = instrIter.next();

            // 确保仍在本函数体内
            if (!func.getBody().contains(instr.getAddress())) {
                break;
            }

            String mnemonic = instr.getMnemonicString().toUpperCase();
            byte[] raw = instr.getBytes();

            // 收集该指令的字节
            for (byte b : raw) {
                hexBuilder.append(String.format("%02X ", b));
            }
            totalBytes += raw.length;

            // 判断停止条件：
            // 遇到任何跳转/返回指令，且已经满足最小长度 → 停止
            // CALL 不停止（允许穿越 CALL 继续收集）
            boolean isJump = mnemonic.startsWith("J")     // JZ, JNZ, JMP, JG 等
                          || mnemonic.equals("RET")
                          || mnemonic.equals("RETN")
                          || mnemonic.equals("RETF");

            // JMP 是无条件跳转，遇到后必须停止（即使不足32字节）
            boolean isUnconditionalJump = mnemonic.equals("JMP");

            if (isUnconditionalJump) {
                done = true;
            } else if (isJump && totalBytes >= MIN_FINGERPRINT_BYTES) {
                done = true;
            }
        }

        // 4. 输出结果
        println("");
        println("===== 指纹提取结果 =====");
        println("[+] 函数名称    : " + func.getName());
        println("[+] 入口地址    : 0x" + entryPoint.toString().toUpperCase());
        println("[+] RVA         : 0x" + Long.toHexString(rva).toUpperCase());
        println("[+] 指纹长度    : " + totalBytes + " 字节");
        println("[+] 指纹字节序列 (Frida 格式):");
        println("    " + hexBuilder.toString().trim());
        println("");
        println("===== 写入数据库的 JSON 片段 =====");
        println("{");
        println("  \"function\": \"" + func.getName() + "\",");
        println("  \"rva\": \"0x" + Long.toHexString(rva).toUpperCase() + "\",");
        println("  \"fingerprint\": \"" + hexBuilder.toString().trim() + "\",");
        println("  \"fingerprint_len\": " + totalBytes);
        println("}");
    }
}