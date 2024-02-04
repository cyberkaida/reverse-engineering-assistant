package reva.RevaProtocol;

public class RevaGetReferences extends RevaMessage {
    public String address_or_symbol;
    public int size;

    public RevaGetReferences() {
        message_type = "RevaGetReferenes";
    }
}