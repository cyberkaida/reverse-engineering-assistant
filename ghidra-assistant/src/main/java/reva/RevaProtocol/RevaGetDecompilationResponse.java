package reva.RevaProtocol;
import java.util.List;

public class RevaGetDecompilationResponse extends RevaMessageResponse {

    public long address;
    public String decompilation;
    public String function;
    public String function_signature;

    public List<String> incoming_calls;
    public List<String> outgoing_calls;
    public List<String> data_references;

    public RevaGetDecompilationResponse(RevaMessage respondingTo) {
        super(respondingTo);
        message_type = "RevaGetDecompilationResponse";
    }
}
