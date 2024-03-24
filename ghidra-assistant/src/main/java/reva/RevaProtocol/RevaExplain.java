package reva.RevaProtocol;

public class RevaExplain extends RevaMessage {
    public RevaLocation location;
    public RevaExplain() {
        message_type = "RevaExplain";
    }
}
