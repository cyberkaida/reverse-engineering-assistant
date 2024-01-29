package reva.RevaMessageHandlers;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import reva.RevaService;
import reva.RevaProtocol.RevaGetDataAtAddress;
import reva.RevaProtocol.RevaGetDataAtAddressResponse;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

public class RevaGetDataAtAddressHandler extends RevaMessageHandler {
    public RevaGetDataAtAddressHandler(RevaService service) {
        super(service);
    }

    @Override
    public RevaMessageResponse handleMessage(RevaMessage message) {
        RevaGetDataAtAddress getDataAtAddress = (RevaGetDataAtAddress) message;
        RevaGetDataAtAddressResponse response = new RevaGetDataAtAddressResponse(getDataAtAddress);


        Address address = service.currentProgram.getAddressFactory().getAddress(getDataAtAddress.address);
        int length = getDataAtAddress.size;
        byte[] data = new byte[length];
        Symbol symbol = service.currentProgram.getSymbolTable().getPrimarySymbol(address);
        String symbol_name = symbol != null ? symbol.getName() : null;
        try {
            service.currentProgram.getMemory().getBytes(address, data);
            response.address = address.getUnsignedOffset();
            response.data = NumericUtilities.convertBytesToString(data);
            response.symbol = symbol_name;
        } catch (MemoryAccessException e) {
            Msg.error(this, "Failed to read memory at address " + address.toString());
            response.error_message = "Failed to read memory at address " + address.toString();
        }

        return response;
    }
}
