package reva.RevaProtocol;
import java.util.List;
import java.util.ArrayList;

public class RevaGetDecompilationResponse extends RevaMessageResponse {
    public class RevaVariable {
        public String name;
        public String data_type;
        public String storage;
        public int size;
        public RevaVariable() {};
    }
    public long address;
    public String decompilation;
    public String listing;
    public String function;
    public String function_signature;

    public List<String> incoming_calls;
    public List<String> outgoing_calls;
    public List<String> data_references;

    public List<RevaVariable> variables;

    public RevaGetDecompilationResponse(RevaMessage respondingTo) {
        super(respondingTo);
        variables = new ArrayList<RevaVariable>();
        message_type = "RevaGetDecompilationResponse";
    }
}
