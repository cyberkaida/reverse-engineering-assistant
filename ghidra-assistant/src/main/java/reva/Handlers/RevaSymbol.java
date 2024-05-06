package reva.Handlers;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import io.grpc.stub.StreamObserver;
import reva.RevaPlugin;
import reva.protocol.RevaGetSymbols.RevaGetSymbolsRequest;
import reva.protocol.RevaGetSymbols.RevaGetSymbolsResponse;
import reva.protocol.RevaGetSymbols.RevaSetSymbolNameRequest;
import reva.protocol.RevaGetSymbols.RevaSetSymbolNameResponse;
import reva.protocol.RevaGetSymbols.RevaSymbolRequest;
import reva.protocol.RevaGetSymbols.RevaSymbolResponse;
import reva.protocol.RevaToolSymbolServiceGrpc.RevaToolSymbolServiceImplBase;


public class RevaSymbol extends RevaToolSymbolServiceImplBase {
    RevaPlugin plugin;

    public RevaSymbol(RevaPlugin plugin) {
        super();
        this.plugin = plugin;
    }

    @Override
    public void getSymbols(RevaGetSymbolsRequest request, StreamObserver<RevaGetSymbolsResponse> responseObserver) {
        // Get the program, get the symbols and send them back
        RevaGetSymbolsResponse.Builder response = RevaGetSymbolsResponse.newBuilder();

        Program currentProgram = this.plugin.getCurrentProgram();
        currentProgram.getSymbolTable().getSymbolIterator(true).forEach(
            symbol -> {
                response.addSymbols(symbol.getName(true));
            }
        );

        responseObserver.onNext(response.build());
        responseObserver.onCompleted();
    }

    @Override
    public void setSymbolName(RevaSetSymbolNameRequest request,
            StreamObserver<RevaSetSymbolNameResponse> responseObserver) {

        // Get the program, get the symbol and set the name
        RevaSetSymbolNameResponse.Builder response = RevaSetSymbolNameResponse.newBuilder();

        Program currentProgram = this.plugin.getCurrentProgram();
        String newSymbolName = request.getNewName();

        Address address = this.plugin.addressFromAddressOrSymbol(request.getOldNameOrAddress());

        try {
            // TODO: Does this replace the existing symbol?
            currentProgram.getSymbolTable().createLabel(address, newSymbolName, SourceType.ANALYSIS);
        } catch (InvalidInputException e) {
            // TODO: Send back to ReVa
            Msg.error(this, "Error setting symbol name: " + request.toString(), e);
        }

        responseObserver.onNext(response.build());
        responseObserver.onCompleted();
    }

    @Override
    public void getSymbol(RevaSymbolRequest request, StreamObserver<RevaSymbolResponse> responseObserver) {
        RevaSymbolResponse.Builder response = RevaSymbolResponse.newBuilder();

        Program currentProgram = this.plugin.getCurrentProgram();
        Address address = this.plugin.addressFromAddressOrSymbol(request.getAddressOrName());

        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
        if (symbol != null) {
            response.setName(symbol.getName());
            response.setAddress(symbol.getAddress().toString());

            if (currentProgram.getListing().getDataAt(address) != null) {
                response.setType(reva.protocol.RevaGetSymbols.SymbolType.DATA);
            } else if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                response.setType(reva.protocol.RevaGetSymbols.SymbolType.FUNCTION);
            } else if (symbol.getSymbolType() == SymbolType.LABEL) {
                response.setType(reva.protocol.RevaGetSymbols.SymbolType.LABEL);
            }
        }

        responseObserver.onNext(response.build());
        responseObserver.onCompleted();
    }

}
