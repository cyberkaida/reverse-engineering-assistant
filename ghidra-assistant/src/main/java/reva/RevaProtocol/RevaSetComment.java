package reva.RevaProtocol;

public class RevaSetComment extends RevaMessage {
    public String comment = null;
    public String address_or_symbol = null;
    public RevaSetComment() {
        message_type = "RevaSetComment";
    }
}
