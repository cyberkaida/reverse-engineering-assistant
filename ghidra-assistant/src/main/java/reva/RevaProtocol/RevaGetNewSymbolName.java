package reva.RevaProtocol;

public class RevaGetNewSymbolName extends RevaMessage {
    public String symbol_name;
    public RevaGetNewSymbolName() {
        message_type = "RevaGetNewSymbolName";
    }
}
