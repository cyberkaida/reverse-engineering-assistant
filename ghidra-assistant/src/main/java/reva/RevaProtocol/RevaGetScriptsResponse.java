package reva.RevaProtocol;

import java.util.List;
import java.util.ArrayList;

public class RevaGetScriptsResponse extends RevaMessageResponse {
    public class Script {
        public String name;
        public String description = null;
        public String path = null;
        public Script() {};
    }

    public List<Script> scripts;

    public RevaGetScriptsResponse(RevaMessage respondingTo) {
        super(respondingTo);
        message_type = "RevaGetScriptsResponse";
        this.scripts = new ArrayList<RevaGetScriptsResponse.Script>();
    }
}
