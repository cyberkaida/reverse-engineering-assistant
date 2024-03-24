package reva.RevaMessageHandlers;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import reva.RevaService;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;
import reva.RevaProtocol.RevaSetComment;
import reva.RevaProtocol.RevaSetCommentResponse;

public class RevaSetCommentHandler extends RevaMessageHandler {
    public RevaSetCommentHandler(RevaService service) {
        super(service);
    }

    @Override
    public RevaMessageResponse handleMessage(RevaMessage message) {
        RevaSetComment request = (RevaSetComment) message;
        RevaSetCommentResponse response = new RevaSetCommentResponse(request);

        Address address = this.addressFromAddressOrSymbol(request.address_or_symbol);

        if (address == null) {
            response.error_message = "No address found for " + request.address_or_symbol;
            return response;
        }

        FlatProgramAPI api = new FlatProgramAPI(service.currentProgram);

        String new_comment = request.comment;
        String current_comment = api.getPlateComment(address);
        if (current_comment != null) {
            new_comment = current_comment + "\n" + new_comment;
        }
        api.setPlateComment(address, new_comment);

        Msg.info(this, "Set comment " + request.comment + " at " + address.toString());
        return response;
    }
}
