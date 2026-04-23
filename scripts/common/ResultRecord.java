public class ResultRecord {
    public final String type;
    public final String functionName;
    public final String rva;
    public final String fingerprint;
    public final String note;

    public ResultRecord(String type, String functionName, String rva, String fingerprint, String note) {
        this.type = type;
        this.functionName = functionName;
        this.rva = rva;
        this.fingerprint = fingerprint;
        this.note = note;
    }
}



