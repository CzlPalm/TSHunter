import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class TLShunterAnalyzer extends GhidraScript {

    private static final String VERSION = "0.3.0-hkdf-xval";

    // TLS 1.3 标签：每个都被 BoringSSL 的核心 derive_secret 接收，
    // 而各个 wrapper（derive_handshake_secrets / derive_app_secrets 等）只使用其中 1~2 个。
    // 四标签 XREF 函数集合的交集将唯一指向核心 derive_secret。
    private static final List<String> HKDF_TLS13_LABELS = List.of(
        "c hs traffic",
        "s hs traffic",
        "c ap traffic",
        "s ap traffic"
    );

    private static class FunctionRef {
        Function function;
        Address referenceAddress;

        FunctionRef(Function function, Address referenceAddress) {
            this.function = function;
            this.referenceAddress = referenceAddress;
        }
    }

    private static class ResultRecord {
        String type;
        String functionName;
        String rva;
        String fingerprint;
        String note;

        ResultRecord(String type, String functionName, String rva, String fingerprint, String note) {
            this.type = type;
            this.functionName = functionName;
            this.rva = rva;
            this.fingerprint = fingerprint;
            this.note = note;
        }
    }

    private final Map<String, ResultRecord> results = new LinkedHashMap<>();

    @Override
    protected void run() throws Exception {
        println("TLShunter integrated analyzer v" + VERSION);
        println("[*] Binary: " + currentProgram.getName());

        identifyHKDF();
        analyzeSslLogSecret();
        identifyPRF();
        identifyKeyExpansion();

        println("[*] Analysis finished.");
    }

    private void identifyHKDF() {
        println("[*] HKDF: 开始识别...");

        Map<String, Set<Function>> funcsPerLabel = new LinkedHashMap<>();
        for (String label : HKDF_TLS13_LABELS) {
            Set<Function> funcs = new LinkedHashSet<>();
            List<Address> addrs = findAllStringsInReadonlyData(label);
            for (Address addr : addrs) {
                funcs.addAll(getReferencingFunctions(addr));
            }
            funcsPerLabel.put(label, funcs);
            println("[*] HKDF: 标签 \"" + label + "\" XREF 函数数 = " + funcs.size());
        }

        Set<Function> fourWay = null;
        for (Set<Function> s : funcsPerLabel.values()) {
            if (fourWay == null) {
                fourWay = new LinkedHashSet<>(s);
            } else {
                fourWay.retainAll(s);
            }
        }
        Function hkdfFunc = pickBestFunctionByXrefs(fourWay != null ? fourWay : new LinkedHashSet<Function>());
        if (hkdfFunc != null) {
            println("[*] HKDF: 四标签交叉验证命中 → " + hkdfFunc.getName());
            emitResult("HKDF", hkdfFunc, "TLS 1.3 Derive-Secret (cross-validated)");
            return;
        }

        Set<Function> hsOnly = new LinkedHashSet<>(funcsPerLabel.get("c hs traffic"));
        hsOnly.retainAll(funcsPerLabel.get("s hs traffic"));
        hkdfFunc = pickBestFunctionByXrefs(hsOnly);
        if (hkdfFunc != null) {
            println("[*] HKDF: 握手标签二重交集命中 → " + hkdfFunc.getName());
            emitResult("HKDF", hkdfFunc, "TLS 1.3 Derive-Secret (handshake-label intersection)");
            return;
        }

        Set<Function> sHsOnly = funcsPerLabel.get("s hs traffic");
        hkdfFunc = pickBestFunctionByXrefs(sHsOnly);
        if (hkdfFunc != null) {
            println("[*] HKDF: 单标签入度最大回退 → " + hkdfFunc.getName());
            emitResult("HKDF", hkdfFunc, "TLS 1.3 Derive-Secret (fallback, may need verification)");
            return;
        }

        println("[-] HKDF: 所有策略均未命中");
    }

    private void analyzeSslLogSecret() {
        FunctionRef selected = findSslLogSecretCandidate();
        if (selected == null || selected.function == null) {
            println("[WARN] type=SSL_LOG_SECRET status=not_found");
            return;
        }

        emitResult("SSL_LOG_SECRET", selected.function, null);
    }

    private void identifyPRF() {
        println("[*] PRF: 开始识别...");

        List<Address> masterSecretAddrs = findAllStringsInReadonlyData("master secret");
        List<Address> extMasterSecretAddrs = findAllStringsInReadonlyData("extended master secret");

        Set<Function> msFuncs = new LinkedHashSet<>();
        Set<Function> emsFuncs = new LinkedHashSet<>();

        for (Address addr : masterSecretAddrs) {
            msFuncs.addAll(getReferencingFunctions(addr));
        }
        for (Address addr : extMasterSecretAddrs) {
            emsFuncs.addAll(getReferencingFunctions(addr));
        }

        Set<Function> intersection = new LinkedHashSet<>(msFuncs);
        intersection.retainAll(emsFuncs);
        Function prfFunc = pickBestFunctionByXrefs(intersection);
        if (prfFunc != null) {
            println("[*] PRF: 双标签交叉验证命中 → " + prfFunc.getName());
            emitResult("PRF", prfFunc, "TLS 1.2 Unified PRF (cross-validated)");
            return;
        }

        for (Address addr : masterSecretAddrs) {
            if (!isStandaloneString(addr)) {
                continue;
            }
            Set<Function> funcs = getReferencingFunctions(addr);
            Function standalone = pickBestFunctionByXrefs(funcs);
            if (standalone != null) {
                println("[*] PRF: 独立字符串 XREF 命中 → " + standalone.getName());
                emitResult("PRF", standalone, "TLS 1.2 PRF (standalone string XREF)");
                return;
            }
        }

        Function best = pickBestFunctionByXrefs(msFuncs);
        if (best != null) {
            println("[*] PRF: fallback XREF 命中 → " + best.getName());
            emitResult("PRF", best, "TLS 1.2 PRF (fallback, may need verification)");
            return;
        }

        println("[-] PRF: 所有策略均未命中");
    }

    private void identifyKeyExpansion() {
        println("[*] KEY_EXPANSION: 开始识别...");

        List<Address> addrs = findAllStringsInReadonlyData("key expansion");
        for (Address addr : addrs) {
            Set<Function> funcs = getReferencingFunctions(addr);
            Function best = pickBestFunctionByXrefs(funcs);
            if (best != null) {
                String note = "TLS 1.2 key block derivation";
                if (isSameAsPrf(best)) {
                    note = "shared with PRF";
                }
                emitResult("KEY_EXPANSION", best, note);
                return;
            }
        }

        println("[-] KEY_EXPANSION: 未找到");
    }

    private FunctionRef findSslLogSecretCandidate() {
        String[] strings = {"EXPORTER_SECRET", "CLIENT_RANDOM"};

        for (String needle : strings) {
            List<FunctionRef> refs = findFunctionsUsingString(needle);
            if (refs.isEmpty()) {
                Address rodataAddress = findStringInReadonlyData(needle);
                if (rodataAddress != null) {
                    refs = collectReferencingFunctions(rodataAddress);
                }
            }

            for (FunctionRef ref : refs) {
                if (ref.function == null || ref.referenceAddress == null) {
                    continue;
                }
                Function called = findFirstCalledFunctionAfterReference(ref.function, ref.referenceAddress);
                if (called != null) {
                    return new FunctionRef(called, ref.referenceAddress);
                }
                return ref;
            }
        }

        return null;
    }

    private void emitResult(String type, Function function, String note) {
        String fingerprint = extractFingerprint(function);
        String rva = getRva(function.getEntryPoint());
        ResultRecord record = new ResultRecord(type, function.getName(), rva, fingerprint, note);
        results.put(type, record);

        String line = "[RESULT] type=" + record.type
            + " function=" + record.functionName
            + " rva=" + record.rva
            + " fingerprint=" + record.fingerprint;
        if (record.note != null && !record.note.isEmpty()) {
            line += " note=" + record.note.replace(' ', '_');
        }
        println(line);
    }

    private List<FunctionRef> findFunctionsUsingString(String target) {
        List<FunctionRef> matches = new ArrayList<>();
        Listing listing = currentProgram.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);

        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            if (!"string".equalsIgnoreCase(data.getDataType().getName())) {
                continue;
            }

            Object value = data.getValue();
            if (value == null) {
                continue;
            }

            String stringValue = value.toString();
            if (!target.equals(stringValue) && !stringValue.contains(target)) {
                continue;
            }

            matches.addAll(collectReferencingFunctions(data.getAddress()));
        }

        return dedupe(matches);
    }

    private List<FunctionRef> collectReferencingFunctions(Address targetAddress) {
        List<FunctionRef> refs = new ArrayList<>();
        ReferenceManager referenceManager = currentProgram.getReferenceManager();
        ReferenceIterator references = referenceManager.getReferencesTo(targetAddress);

        while (references.hasNext()) {
            Reference reference = references.next();
            Address from = reference.getFromAddress();
            Function function = getFunctionContaining(from);

            if (function != null) {
                refs.add(new FunctionRef(function, from));
                continue;
            }

            FunctionRef traced = traceDataReference(from, 4);
            if (traced != null && traced.function != null) {
                refs.add(traced);
            }
        }

        return dedupe(refs);
    }

    private Set<Function> getReferencingFunctions(Address targetAddress) {
        Set<Function> functions = new LinkedHashSet<>();
        for (FunctionRef ref : collectReferencingFunctions(targetAddress)) {
            if (ref != null && ref.function != null) {
                functions.add(ref.function);
            }
        }
        return functions;
    }

    private FunctionRef traceDataReference(Address start, int maxAttempts) {
        Address current = start;
        int step = currentProgram.getDefaultPointerSize();
        ReferenceManager referenceManager = currentProgram.getReferenceManager();

        for (int i = 0; i < maxAttempts && current != null; i++) {
            ReferenceIterator refs = referenceManager.getReferencesTo(current);
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Function function = getFunctionContaining(ref.getFromAddress());
                if (function != null) {
                    return new FunctionRef(function, ref.getFromAddress());
                }
            }

            try {
                current = current.subtract(step);
            } catch (Exception ex) {
                return null;
            }
        }

        return null;
    }

    private List<FunctionRef> dedupe(List<FunctionRef> refs) {
        List<FunctionRef> output = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (FunctionRef ref : refs) {
            if (ref == null || ref.function == null) {
                continue;
            }
            String key = ref.function.getEntryPoint().toString() + "@" + (ref.referenceAddress == null ? "" : ref.referenceAddress.toString());
            if (seen.add(key)) {
                output.add(ref);
            }
        }
        return output;
    }

    private Address findStringInReadonlyData(String target) {
        List<Address> all = findAllStringsInReadonlyData(target);
        return all.isEmpty() ? null : all.get(0);
    }

    private List<Address> findAllStringsInReadonlyData(String target) {
        List<Address> results = new ArrayList<>();
        Memory memory = currentProgram.getMemory();
        byte[] needle = target.getBytes(StandardCharsets.US_ASCII);
        byte[] needleWithNull = appendByte(needle, (byte) 0x00);

        for (MemoryBlock block : getReadonlyDataBlocks()) {
            findAllPatternInBlock(memory, block, needleWithNull, results);
        }
        if (!results.isEmpty()) {
            return results;
        }

        for (MemoryBlock block : getReadonlyDataBlocks()) {
            findAllPatternInBlock(memory, block, needle, results);
        }
        return results;
    }

    private void findAllPatternInBlock(Memory memory, MemoryBlock block, byte[] pattern, List<Address> results) {
        Address current = block.getStart();
        Address lastStart = block.getEnd().subtract(pattern.length - 1);

        try {
            while (current.compareTo(lastStart) <= 0) {
                byte[] bytes = new byte[pattern.length];
                int read = memory.getBytes(current, bytes);
                if (read == pattern.length && matches(bytes, pattern)) {
                    results.add(current);
                    current = current.add(pattern.length);
                } else {
                    current = current.add(1);
                }
            }
        } catch (Exception ex) {
            // Ignore block boundary issues and continue.
        }
    }

    private boolean isStandaloneString(Address addr) {
        if (addr.getOffset() == 0) {
            return true;
        }
        try {
            Address prev = addr.subtract(1);
            byte prevByte = currentProgram.getMemory().getByte(prev);
            return prevByte == 0x00;
        } catch (Exception ex) {
            return true;
        }
    }

    private List<MemoryBlock> getReadonlyDataBlocks() {
        List<MemoryBlock> blocks = new ArrayList<>();
        String[] names = {".rodata", ".rdata", "__cstring", "__const"};
        Memory memory = currentProgram.getMemory();

        for (String name : names) {
            MemoryBlock block = memory.getBlock(name);
            if (block != null) {
                blocks.add(block);
            }
        }

        if (!blocks.isEmpty()) {
            return blocks;
        }

        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isRead() && !block.isWrite()) {
                blocks.add(block);
            }
        }

        return blocks;
    }

    private boolean matches(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }

    private byte[] appendByte(byte[] original, byte value) {
        byte[] result = new byte[original.length + 1];
        System.arraycopy(original, 0, result, 0, original.length);
        result[original.length] = value;
        return result;
    }

    private Function findFirstCalledFunctionAfterReference(Function container, Address referenceAddress) {
        Listing listing = currentProgram.getListing();
        Instruction instruction = listing.getInstructionAt(referenceAddress);
        if (instruction == null) {
            instruction = listing.getInstructionAfter(referenceAddress);
        }

        while (instruction != null && container.getBody().contains(instruction.getAddress())) {
            if (instruction.getFlowType().isCall()) {
                Address[] flows = instruction.getFlows();
                if (flows != null && flows.length > 0) {
                    Function called = getFunctionAt(flows[0]);
                    if (called != null) {
                        return called;
                    }
                }
            }
            instruction = instruction.getNext();
        }

        return null;
    }

    private String extractFingerprint(Function function) {
        Address entry = function.getEntryPoint();
        int length = getLengthUntilStop(function);
        if (length <= 0) {
            length = 32;
        }

        byte[] bytes = new byte[length];
        try {
            currentProgram.getMemory().getBytes(entry, bytes);
        } catch (MemoryAccessException ex) {
            return "";
        }

        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            if (builder.length() > 0) {
                builder.append(' ');
            }
            builder.append(String.format("%02X", b & 0xFF));
        }
        return builder.toString();
    }

    private int getLengthUntilStop(Function function) {
        Listing listing = currentProgram.getListing();
        InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
        int length = 0;
        boolean foundStop = false;

        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            length += instruction.getLength();

            if (instruction.getFlowType().isJump() || instruction.getFlowType().isConditional() || instruction.getFlowType().isCall()) {
                Address[] flows = instruction.getFlows();
                if (flows != null && flows.length > 0 && function.getBody().contains(flows[0])) {
                    continue;
                }
                foundStop = true;
                break;
            }
        }

        if (!foundStop) {
            return Math.min(length, 64);
        }
        return length;
    }

    private int countXrefsTo(Function function) {
        int count = 0;
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());
        while (refs.hasNext()) {
            Reference ref = refs.next();
            if (ref.getReferenceType().isCall()) {
                count++;
            }
        }
        return count;
    }

    private Function pickBestFunctionByXrefs(Set<Function> functions) {
        Function best = null;
        int bestCount = -1;

        for (Function function : functions) {
            int currentCount = countXrefsTo(function);
            if (currentCount > bestCount) {
                best = function;
                bestCount = currentCount;
            }
        }

        return best;
    }

    private boolean isSameAsPrf(Function function) {
        ResultRecord prf = results.get("PRF");
        if (prf == null) {
            return false;
        }
        return prf.rva.equals(getRva(function.getEntryPoint()));
    }

    private String getRva(Address address) {
        long imageBase = currentProgram.getImageBase().getOffset();
        long rva = address.getOffset() - imageBase;
        return String.format("0x%08X", rva);
    }
}
