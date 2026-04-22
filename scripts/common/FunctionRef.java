import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class FunctionRef {
    public final Function function;
    public final Address referenceAddress;

    public FunctionRef(Function function, Address referenceAddress) {
        this.function = function;
        this.referenceAddress = referenceAddress;
    }
}


