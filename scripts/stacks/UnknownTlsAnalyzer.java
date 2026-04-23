import ghidra.app.script.GhidraScript;

import java.util.List;

public class UnknownTlsAnalyzer extends StackAnalyzer {
    public UnknownTlsAnalyzer(GhidraScript script) {
        super(script);
    }

    @Override
    public double detectConfidence() {
        return 0.0;
    }

    @Override
    public List<ResultRecord> analyze() {
        throw new UnsupportedOperationException("TLS stack not detected");
    }

    @Override
    public String getName() {
        return "unknown";
    }
}


