package reva.RevaProtocol;

public class RevaSetSymbolNameResponse extends RevaMessageResponse {

    public RevaSetSymbolNameResponse(RevaMessage message) {
        super(message);
        message_type = "RevaSetSymbolNameResponse";
    }
}
