package reva.RevaProtocol;

public class RevaGetNewSymbolNameResponse extends RevaMessageResponse {

    public RevaGetNewSymbolNameResponse(RevaMessage message) {
        super(message);
        message_type = "RevaGetNewSymbolNameResponse";
    }
}
