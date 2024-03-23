package reva.RevaMessageHandlers;

import reva.RevaService;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;

public class RevaGetScriptsHandler extends RevaMessageHandler {

    public RevaGetScriptsHandler(RevaService service) {
        super(service);
    }

    @Override
    public RevaMessageResponse handleMessage(RevaMessage message) {
        
        return null;
    }

}
