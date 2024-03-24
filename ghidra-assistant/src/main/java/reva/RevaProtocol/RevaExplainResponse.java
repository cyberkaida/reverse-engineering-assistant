package reva.RevaProtocol;

public class RevaExplainResponse extends RevaMessageResponse {
    public RevaExplainResponse(RevaMessage respondingTo) {
        super(respondingTo);
        message_type = "RevaExplainResponse";
    }
}
