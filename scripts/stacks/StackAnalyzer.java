import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;

import java.util.List;

public abstract class StackAnalyzer {
    protected final GhidraScript script;
    protected final Program program;

    public StackAnalyzer(GhidraScript script) {
        this.script = script;
        this.program = script.getCurrentProgram();
    }

    public abstract double detectConfidence();

    public abstract List<ResultRecord> analyze();

    public abstract String getName();
}



