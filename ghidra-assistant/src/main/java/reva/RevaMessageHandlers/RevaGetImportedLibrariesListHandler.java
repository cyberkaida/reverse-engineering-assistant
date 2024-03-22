package reva.RevaMessageHandlers;

import ghidra.util.Msg;
import reva.RevaService;
import reva.RevaProtocol.RevaGetImportedLibrariesList;
import reva.RevaProtocol.RevaGetImportedLibrariesListResponse;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;
import java.util.List;
import java.util.ArrayList;

public class RevaGetImportedLibrariesListHandler extends RevaMessageHandler {

	public RevaGetImportedLibrariesListHandler(RevaService service) {
		super(service);
	}

	@Override
	public RevaMessageResponse handleMessage(RevaMessage message) {
		RevaGetImportedLibrariesList request = (RevaGetImportedLibrariesList) message;
		RevaGetImportedLibrariesListResponse response = new RevaGetImportedLibrariesListResponse(request);

		int page = request.page;
		int page_size = request.page_size;

		List<String> list = new ArrayList<String>();

		int start = (page - 1) * page_size;
		int end = start + page_size;

		int index = 0;

		for (String libraryName : service.currentProgram.getExternalManager().getExternalLibraryNames()) {
			if (index >= start && index < end) {
				list.add(libraryName);
			}

			if (index >= end) {
				break;
			}

			index += 1;
		}

		// Handle if ReVa requested a page that is higher than the number of pages
		if (end > index) {
			response.error_message = "Page is greater than the maximum page count. There are " + index
					+ " imported libraries.";
		}

		response.list = list;

		Msg.info(this, "Responding with imported library list");
		return response;
	}

}
