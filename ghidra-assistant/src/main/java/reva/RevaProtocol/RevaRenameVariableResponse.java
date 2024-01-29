package reva.RevaProtocol;

public class RevaRenameVariableResponse extends RevaMessageResponse {
    public RevaRenameVariableResponse(RevaMessage message) {
        super(message);
        message_type = "RevaRenameVariableResponse";
    }
}
