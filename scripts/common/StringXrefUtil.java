import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class StringXrefUtil {
    private final GhidraScript script;

    public StringXrefUtil(GhidraScript script) {
        this.script = script;
    }

    public List<FunctionRef> findFunctionsUsingString(String target) {
        List<FunctionRef> matches = new ArrayList<>();
        Listing listing = script.getCurrentProgram().getListing();
        DataIterator dataIterator = listing.getDefinedData(true);

        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            String typeName = data.getDataType() == null ? "" : data.getDataType().getName();
            if (!"string".equalsIgnoreCase(typeName) && !typeName.toLowerCase().contains("string")) {
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

        if (!matches.isEmpty()) {
            return dedupe(matches);
        }

        for (Address addr : findAllStringsInReadonlyData(target)) {
            matches.addAll(collectReferencingFunctions(addr));
        }
        return dedupe(matches);
    }

    public List<FunctionRef> collectReferencingFunctions(Address targetAddress) {
        List<FunctionRef> refs = new ArrayList<>();
        ReferenceManager referenceManager = script.getCurrentProgram().getReferenceManager();
        ReferenceIterator references = referenceManager.getReferencesTo(targetAddress);

        while (references.hasNext()) {
            Reference reference = references.next();
            Address from = reference.getFromAddress();
            Function function = script.getFunctionContaining(from);

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

    public Set<Function> getReferencingFunctions(Address targetAddress) {
        Set<Function> functions = new LinkedHashSet<>();
        for (FunctionRef ref : collectReferencingFunctions(targetAddress)) {
            if (ref != null && ref.function != null) {
                functions.add(ref.function);
            }
        }
        return functions;
    }

    public Address findStringInReadonlyData(String target) {
        List<Address> all = findAllStringsInReadonlyData(target);
        return all.isEmpty() ? null : all.get(0);
    }

    public List<Address> findAllStringsInReadonlyData(String target) {
        List<Address> results = new ArrayList<>();
        Memory memory = script.getCurrentProgram().getMemory();
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

    public boolean isStandaloneString(Address addr) {
        if (addr.getOffset() == 0) {
            return true;
        }
        try {
            Address prev = addr.subtract(1);
            byte prevByte = script.getCurrentProgram().getMemory().getByte(prev);
            return prevByte == 0x00;
        } catch (Exception ex) {
            return true;
        }
    }

    public Function findFirstCalledFunctionAfterReference(Function container, Address referenceAddress) {
        Listing listing = script.getCurrentProgram().getListing();
        Instruction instruction = listing.getInstructionAt(referenceAddress);
        if (instruction == null) {
            instruction = listing.getInstructionAfter(referenceAddress);
        }

        while (instruction != null && container.getBody().contains(instruction.getAddress())) {
            if (instruction.getFlowType().isCall()) {
                Address[] flows = instruction.getFlows();
                if (flows != null && flows.length > 0) {
                    Function called = script.getFunctionAt(flows[0]);
                    if (called != null) {
                        return called;
                    }
                }
            }
            instruction = instruction.getNext();
        }

        return null;
    }

    public int countXrefsTo(Function function) {
        int count = 0;
        ReferenceIterator refs = script.getCurrentProgram().getReferenceManager().getReferencesTo(function.getEntryPoint());
        while (refs.hasNext()) {
            Reference ref = refs.next();
            if (ref.getReferenceType().isCall()) {
                count++;
            }
        }
        return count;
    }

    public Function pickBestFunctionByXrefs(Set<Function> functions) {
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

    private FunctionRef traceDataReference(Address start, int maxAttempts) {
        Address current = start;
        int step = script.getCurrentProgram().getDefaultPointerSize();
        ReferenceManager referenceManager = script.getCurrentProgram().getReferenceManager();

        for (int i = 0; i < maxAttempts && current != null; i++) {
            ReferenceIterator refs = referenceManager.getReferencesTo(current);
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Function function = script.getFunctionContaining(ref.getFromAddress());
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

    private List<MemoryBlock> getReadonlyDataBlocks() {
        List<MemoryBlock> blocks = new ArrayList<>();
        String[] names = {".rodata", ".rdata", "__cstring", "__const"};
        Memory memory = script.getCurrentProgram().getMemory();

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
}
