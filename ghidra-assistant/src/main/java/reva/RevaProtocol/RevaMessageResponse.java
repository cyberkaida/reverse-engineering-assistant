package reva.RevaProtocol;
import java.util.UUID;

public class RevaMessageResponse extends RevaMessage {
    public UUID response_to;
    public String error_message;

    public RevaMessageResponse(RevaMessage respondingTo) {
        response_to = respondingTo.message_id;
    }
}
