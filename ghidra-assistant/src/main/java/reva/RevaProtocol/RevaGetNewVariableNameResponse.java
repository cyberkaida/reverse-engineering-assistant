package reva.RevaProtocol;

public class RevaGetNewVariableNameResponse extends RevaMessageResponse {
    public RevaGetNewVariableNameResponse(RevaGetNewVariableName respondingTo) {
        super(respondingTo);
        message_type = "RevaGetNewVariableNameResponse";
    }
}
