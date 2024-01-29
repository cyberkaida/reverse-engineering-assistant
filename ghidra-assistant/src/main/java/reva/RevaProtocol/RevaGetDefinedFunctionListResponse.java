package reva.RevaProtocol;

import java.util.List;

public class RevaGetDefinedFunctionListResponse extends RevaMessageResponse {
    public List<String> function_list;
    public RevaGetDefinedFunctionListResponse(RevaMessage respondingTo) {
        super(respondingTo);
        message_type = "RevaGetDefinedFunctionListResponse";
    }
}
