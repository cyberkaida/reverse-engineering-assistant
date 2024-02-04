package reva.RevaProtocol;

import java.util.List;
import java.util.ArrayList;

public class RevaGetReferencesResponse extends RevaMessageResponse {
    public List<String> references_to;
    public List<String> references_from;
    public RevaGetReferencesResponse(RevaMessage respondingTo) {
        super(respondingTo);
        message_type = "RevaGetReferencesResponse";
        this.references_to = new ArrayList<String>();
        this.references_from = new ArrayList<String>();
    }
}
