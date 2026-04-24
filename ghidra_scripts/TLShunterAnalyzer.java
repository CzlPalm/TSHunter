import ghidra.app.script.GhidraScript;

import java.util.List;

public class TLShunterAnalyzer extends GhidraScript {

    private static final String VERSION = "0.6.0-modular";

    @Override
    protected void run() throws Exception {
        println("TLShunter integrated analyzer v" + VERSION);
        println("[*] Binary: " + currentProgram.getName());
        println("[*] Image base: " + currentProgram.getImageBase());

        TlsStackDetector.Detection det = TlsStackDetector.detect(this);
        println(String.format("[*] Selected: %s (confidence=%.2f)", det.stackName, det.confidence));
        println(String.format("[DETECT] stack=%s confidence=%.2f", det.stackName, det.confidence));

        List<ResultRecord> records;
        try {
            records = det.analyzer.analyze();
        } catch (UnsupportedOperationException e) {
            println("[!] " + det.stackName + " analyzer not yet implemented: " + e.getMessage());
            records = List.of();
        }

        ResultEmitter emitter = new ResultEmitter(this);
        for (ResultRecord record : records) {
            emitter.emit(record);
        }

        println("[*] Analysis finished. Hook points: " + records.size());
    }
}
