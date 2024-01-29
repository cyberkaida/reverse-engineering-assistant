package reva.RevaProtocol;

public class RevaGetNewVariableName extends RevaMessage {
    public RevaVariable variable;
    public String function_name;
    public RevaGetNewVariableName() {
        message_type = "RevaGetNewVariableName";
    }
}