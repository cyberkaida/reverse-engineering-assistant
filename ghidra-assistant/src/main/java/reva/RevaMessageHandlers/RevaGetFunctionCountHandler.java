package reva.RevaMessageHandlers;

import ghidra.util.Msg;
import reva.RevaService;
import reva.RevaProtocol.RevaGetFunctionCount;
import reva.RevaProtocol.RevaGetFunctionCountResponse;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;

public class RevaGetFunctionCountHandler extends RevaMessageHandler {

    public RevaGetFunctionCountHandler(RevaService service) {
        super(service);
    }

    @Override
    public RevaMessageResponse handleMessage(RevaMessage message) {
        RevaGetFunctionCount request = (RevaGetFunctionCount) message;
        RevaGetFunctionCountResponse response = new RevaGetFunctionCountResponse(request);
        // TODO: Do we need to filter to just defined functions?
        response.function_count = service.currentProgram.getFunctionManager().getFunctionCount();
        Msg.info(this, "Function count: " + response.function_count);
        return response;
    }
    
}
