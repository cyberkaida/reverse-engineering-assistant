package reva.RevaProtocol;

public class RevaHeartbeatResponse extends RevaMessageResponse {
    public RevaHeartbeatResponse(RevaHeartbeat respondingTo) {
        super(respondingTo);
        message_type = "RevaHeartbeatResponse";
    }
}