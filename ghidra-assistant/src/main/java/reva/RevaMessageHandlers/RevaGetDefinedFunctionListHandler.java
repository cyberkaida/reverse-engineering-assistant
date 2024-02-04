package reva.RevaMessageHandlers;

import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import reva.RevaService;
import reva.RevaProtocol.RevaGetDefinedFunctionList;
import reva.RevaProtocol.RevaGetDefinedFunctionListResponse;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;
import java.util.List;
import java.util.ArrayList;

public class RevaGetDefinedFunctionListHandler extends RevaMessageHandler {

    public RevaGetDefinedFunctionListHandler(RevaService service) {
        super(service);
    }

    @Override
    public RevaMessageResponse handleMessage(RevaMessage message) {
        RevaGetDefinedFunctionList request = (RevaGetDefinedFunctionList) message;
        RevaGetDefinedFunctionListResponse response = new RevaGetDefinedFunctionListResponse(request);

        int page = request.page;
        int page_size = request.page_size;

        List<String> function_list = new ArrayList<String>();

        int start = (page - 1) * page_size;
        int end = start + page_size;

        int index = 0;
        for (Function function : service.currentProgram.getFunctionManager().getFunctions(true)) {
            if (index >= start && index < end) {
                function_list.add(function.getName(true));
            }

            if (index >= end) {
                break;
            }

            index += 1;
        }

        // Handle if ReVa requested a page that is higher than the number of pages
        if (end > index) {
            response.error_message = "Page is greater than the maximum page count. There are " + index + " functions.";
        }

        response.function_list = function_list;

        Msg.info(this, "Responding with function list");
        return response;
    }
    
}
