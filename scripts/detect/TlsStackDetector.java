import ghidra.app.script.GhidraScript;

import java.util.List;

public class TlsStackDetector {
    public static class Detection {
        public String stackName;
        public double confidence;
        public StackAnalyzer analyzer;
    }

    public static Detection detect(GhidraScript script) {
        List<StackAnalyzer> candidates = List.of(
            new BoringSslAnalyzer(script),
            new OpenSslAnalyzer(script),
            new NssAnalyzer(script),
            new RustlsAnalyzer(script)
        );

        Detection best = null;
        for (StackAnalyzer analyzer : candidates) {
            double confidence = analyzer.detectConfidence();
            script.println(String.format("[*] Detector: %s → confidence %.2f", analyzer.getName(), confidence));
            if (best == null || confidence > best.confidence) {
                best = new Detection();
                best.stackName = analyzer.getName();
                best.confidence = confidence;
                best.analyzer = analyzer;
            }
        }

        if (best == null || best.confidence <= 0.0) {
            Detection unknown = new Detection();
            unknown.stackName = "unknown";
            unknown.confidence = 0.0;
            unknown.analyzer = new UnknownTlsAnalyzer(script);
            return unknown;
        }

        return best;
    }
}
