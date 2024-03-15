package reva.RevaMessageHandlers;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import reva.RevaService;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;
import reva.RevaProtocol.RevaSetSymbolName;
import reva.RevaProtocol.RevaSetSymbolNameResponse;

public class RevaSetSymbolNameHandler extends RevaMessageHandler {
    public RevaSetSymbolNameHandler(RevaService service) {
        super(service);
    }

    public RevaMessageResponse handleMessage(RevaMessage message) {
        RevaSetSymbolName setSymbolNameMessage = (RevaSetSymbolName) message;
        RevaSetSymbolNameResponse response = new RevaSetSymbolNameResponse(setSymbolNameMessage);
        String oldNameOrAddress = setSymbolNameMessage.old_name_or_address;
        String newName = setSymbolNameMessage.new_name;

        Address address = this.addressFromAddressOrSymbol(oldNameOrAddress);

        if (address == null) {
            response.error_message = "Could not get address for " + oldNameOrAddress;
            return response;
        }

        try {
            Symbol symbol = this.service.currentProgram.getSymbolTable().getPrimarySymbol(address);
            if (symbol == null) {
                this.service.currentProgram.getSymbolTable().createLabel(address, newName, SourceType.ANALYSIS);
                return response;
            } else {
                symbol.setName(newName, SourceType.ANALYSIS);
            }
        } catch (InvalidInputException | DuplicateNameException e) {
            // Let the LLM know what is wrong
            response.error_message = e.getMessage();
        }

        return response;
    }

}
