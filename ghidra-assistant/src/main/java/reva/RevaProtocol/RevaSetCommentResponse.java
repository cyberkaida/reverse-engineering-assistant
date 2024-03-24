package reva.RevaProtocol;

public class RevaSetCommentResponse extends RevaMessageResponse {
    public RevaSetCommentResponse(RevaMessage respondingTo) {
        super(respondingTo);
        message_type = "RevaSetCommentResponse";
    }
}
