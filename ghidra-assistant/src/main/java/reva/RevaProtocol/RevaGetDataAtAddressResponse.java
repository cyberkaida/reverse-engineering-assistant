package reva.RevaProtocol;

public class RevaGetDataAtAddressResponse extends RevaMessageResponse {
    public long address;
    public String data;
    public String symbol;
    public RevaGetDataAtAddressResponse(RevaMessage respondingTo) {
        super(respondingTo);
        message_type = "RevaGetDataAtAddressResponse";
    }
}
