package reva.RevaProtocol;

public class RevaGetFunctionCountResponse extends RevaMessageResponse {
    public int function_count;

    public RevaGetFunctionCountResponse(RevaGetFunctionCount respondingTo) {
        super(respondingTo);
        message_type = "RevaGetFunctionCountResponse";
    }
}
