package reva.RevaMessageHandlers;

import org.python.indexer.Ref;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import reva.RevaService;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaGetReferences;
import reva.RevaProtocol.RevaGetReferencesResponse;
import reva.RevaProtocol.RevaMessageResponse;

public class RevaGetReferencesHandler extends RevaMessageHandler {
    
    public RevaGetReferencesHandler(RevaService service) {
        super(service);
    }

    private String toAddressOrSymbol(Address address) {
        // This method takes the address or symbol and returns the address

        Function function = this.service.currentProgram.getFunctionManager().getFunctionContaining(address);
        Symbol symbol = this.service.currentProgram.getSymbolTable().getPrimarySymbol(address);
        Data data = this.service.currentProgram.getListing().getDataContaining(address);

        if (function != null) {
            return function.getName(true);
        } else if (symbol != null) {
            return symbol.getName(true);
        } else if (data != null) {
            return data.getLabel();
        } else {
            return address.toString();
        }
    }

    public RevaMessageResponse handleMessage(RevaMessage message) {
        // This method takes the message and finds the references to the address or symbol

        RevaGetReferences referencesMessage = (RevaGetReferences) message;
        RevaGetReferencesResponse response = new RevaGetReferencesResponse(referencesMessage);
        String addressOrSymbol = referencesMessage.address_or_symbol;

        Address address = this.addressFromAddressOrSymbol(addressOrSymbol);

        if (address == null) {
            response.error_message = "Could not get address for " + addressOrSymbol;
            return response;
        }

        for (Reference reference : this.service.currentProgram.getReferenceManager().getReferencesTo(address)) {
            response.references_to.add(this.toAddressOrSymbol(reference.getFromAddress()));
        }

        for (Reference reference : this.service.currentProgram.getReferenceManager().getReferencesFrom(address)) {
            response.references_from.add(this.toAddressOrSymbol(reference.getToAddress()));
        }

        return response;
    }

}
