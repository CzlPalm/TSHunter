import ghidra.app.script.GhidraScript;

public class ResultEmitter {
    private final GhidraScript script;

    public ResultEmitter(GhidraScript script) {
        this.script = script;
    }

    public void emit(ResultRecord record) {
        String line = "[RESULT] type=" + record.type
            + " function=" + record.functionName
            + " rva=" + record.rva
            + " fingerprint=" + record.fingerprint;
        if (record.note != null && !record.note.isEmpty()) {
            line += " note=" + record.note.replace(' ', '_');
        }
        script.println(line);
    }
}


