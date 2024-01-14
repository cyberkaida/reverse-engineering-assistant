package reva.RevaProtocol;

/**
 * Request the data at a given address
 */
public class RevaGetDataAtAddress extends RevaMessage {
    public String address;
    public int size;
    public RevaGetDataAtAddress() {
        message_type = "RevaGetDataAtAddress";
    }
}
