import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryAccessException;

public class FingerprintExtractor {
    private final GhidraScript script;

    public FingerprintExtractor(GhidraScript script) {
        this.script = script;
    }

    public String extractFingerprint(Function function) {
        Address entry = function.getEntryPoint();
        int length = getLengthUntilStop(function);
        if (length <= 0) {
            length = 32;
        }

        byte[] bytes = new byte[length];
        try {
            script.getCurrentProgram().getMemory().getBytes(entry, bytes);
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

    public int getLengthUntilStop(Function function) {
        final int MIN_FP = 32;
        final int MAX_CAP = 256;
        final int DEFAULT_ON_ERROR = 32;

        Listing listing = script.getCurrentProgram().getListing();
        Address entry = function.getEntryPoint();
        Instruction instruction = listing.getInstructionAt(entry);
        if (instruction == null) {
            return DEFAULT_ON_ERROR;
        }

        int length = 0;
        while (instruction != null && function.getBody().contains(instruction.getAddress())) {
            length += instruction.getLength();

            String mnemonic = instruction.getMnemonicString().toUpperCase();
            boolean isJmpUncond = mnemonic.equals("JMP");
            boolean isBranchLike = mnemonic.startsWith("J")
                || mnemonic.equals("RET")
                || mnemonic.equals("RETN")
                || mnemonic.equals("RETF");

            if (isJmpUncond) {
                return Math.min(length, MAX_CAP);
            }
            if (isBranchLike && length >= MIN_FP) {
                return Math.min(length, MAX_CAP);
            }
            if (length >= MAX_CAP) {
                return MAX_CAP;
            }

            instruction = instruction.getNext();
        }

        return length > 0 ? Math.min(length, MAX_CAP) : DEFAULT_ON_ERROR;
    }

    public String getRva(Address address) {
        long imageBase = script.getCurrentProgram().getImageBase().getOffset();
        long rva = address.getOffset() - imageBase;
        return String.format("0x%08X", rva);
    }
}


