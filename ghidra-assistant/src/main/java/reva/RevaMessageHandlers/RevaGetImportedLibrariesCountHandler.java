package reva.RevaMessageHandlers;

import ghidra.util.Msg;
import reva.RevaService;
import reva.RevaProtocol.RevaGetImportedLibrariesCount;
import reva.RevaProtocol.RevaGetImportedLibrariesCountResponse;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;

public class RevaGetImportedLibrariesCountHandler extends RevaMessageHandler {

	public RevaGetImportedLibrariesCountHandler(RevaService service) {
		super(service);
	}

	@Override
	public RevaMessageResponse handleMessage(RevaMessage message) {
		RevaGetImportedLibrariesCount request = (RevaGetImportedLibrariesCount) message;
		RevaGetImportedLibrariesCountResponse response = new RevaGetImportedLibrariesCountResponse(request);
		response.count = service.currentProgram.getExternalManager().getExternalLibraryNames().length;
		Msg.info(this, "Imported libraries count: " + response.count);
		return response;
	}

}
