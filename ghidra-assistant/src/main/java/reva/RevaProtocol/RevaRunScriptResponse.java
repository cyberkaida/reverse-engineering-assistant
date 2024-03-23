package reva.RevaProtocol;

public class RevaRunScriptResponse extends RevaMessageResponse {
    public String output;
    public RevaRunScriptResponse(RevaMessage respondingTo) {
        super(respondingTo);
        message_type = "RevaRunScriptResponse";
    }

}
