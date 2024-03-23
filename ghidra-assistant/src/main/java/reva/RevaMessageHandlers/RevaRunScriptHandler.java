package reva.RevaMessageHandlers;

import reva.RevaService;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;

/**
 * This handler allows ReVa to run a python3 script in a Ghidra script
 * context. The script can only write to the database with the needs_write
 * flag set to true.
 * The script is run in an undo context.
 *
 * We will depend on the Ghidrathon plugin to provide the python3 environment.
 * If this is not available, the script we will return an error.
 *
 * When the script is finished its output will be returned to ReVa.
 *
 * If we can, we will display a diff view to show the effect of the script.
 */
public class RevaRunScriptHandler extends RevaMessageHandler {

    public RevaRunScriptHandler(RevaService service) {
        super(service);
    }

    @Override
    public RevaMessageResponse handleMessage(RevaMessage message) {
        return null;
    }
}
