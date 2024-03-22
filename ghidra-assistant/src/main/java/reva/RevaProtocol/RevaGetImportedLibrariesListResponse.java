package reva.RevaProtocol;

import java.util.List;

public class RevaGetImportedLibrariesListResponse extends RevaMessageResponse {
    public List<String> list;
    public RevaGetImportedLibrariesListResponse(RevaMessage respondingTo) {
        super(respondingTo);
        message_type = "RevaGetImportedLibrariesListResponse";
    }
}
