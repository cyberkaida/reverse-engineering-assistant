package reva.RevaProtocol;

public class RevaSetSymbolName extends RevaMessage {
    public String old_name_or_address;
    public String new_name;
    public RevaSetSymbolName() {
        message_type = "RevaSetSymbolName";
    }
}
