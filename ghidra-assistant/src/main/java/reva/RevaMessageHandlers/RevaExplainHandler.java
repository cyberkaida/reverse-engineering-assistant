package reva.RevaMessageHandlers;

import ghidra.util.Msg;
import reva.RevaService;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;

public class RevaExplainHandler extends RevaMessageHandler {

    public RevaExplainHandler(RevaService service) {
        super(service);
    }

    @Override
    public RevaMessageResponse handleMessage(RevaMessage message) {
        Msg.info(this, "Explain message received");
        return null;
    }
}
