package reva.RevaProtocol;

public class RevaGetImportedLibrariesCountResponse extends RevaMessageResponse {
	public int count;

	public RevaGetImportedLibrariesCountResponse(RevaMessage respondingTo) {
		super(respondingTo);
		message_type = "RevaGetImportedLibrariesCountResponse";
	}
}
