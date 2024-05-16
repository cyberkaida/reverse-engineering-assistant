package reva.Handlers;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import reva.RevaPlugin;
import reva.Actions.RevaAction;
import reva.Actions.RevaActionCancelled;
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

        RevaAction action = new RevaAction.Builder()
            .setPlugin(this.plugin)
            .setDescription("Get all symbols")
            .setName("Get Symbols")
            .setOnAccepted(() -> {
                Program currentProgram = this.plugin.getCurrentProgram();
                Msg.info(this, "Getting all symbols");
                currentProgram.getSymbolTable().getSymbolIterator(true).forEach(
                    symbol -> {
                        Msg.info(this, "Found Symbol: " + symbol.getName(true));
                        response.addSymbols(symbol.getName(true));
                    }
                );
                Msg.info(this, "Sending response");
                responseObserver.onNext(response.build());
                responseObserver.onCompleted();
            })
            .setOnRejected(() -> {
                Status status = Status.CANCELLED.withDescription("User rejected the action");
                responseObserver.onError(status.asRuntimeException());
            })
            .build();

        this.plugin.addAction(action);
        action.accept();
    }

    @Override
    public void setSymbolName(RevaSetSymbolNameRequest request,
            StreamObserver<RevaSetSymbolNameResponse> responseObserver) {

        // Get the program, get the symbol and set the name
        RevaSetSymbolNameResponse.Builder response = RevaSetSymbolNameResponse.newBuilder();

        Program currentProgram = this.plugin.getCurrentProgram();
        String newSymbolName = request.getNewName();

        FlatProgramAPI api = new FlatProgramAPI(currentProgram);

        Address address = this.plugin.addressFromAddressOrSymbol(request.getOldNameOrAddress());

        RevaAction action = new RevaAction.Builder()
            .setPlugin(this.plugin)
            .setLocation(address)
            .setDescription("Set the symbol name to " + newSymbolName)
            .setName("Set Symbol Name")
            .setOnAccepted(() -> {
                int transactionId = currentProgram.startTransaction("Set Symbol Name");
                try {
                    // We need to create a database transaction here
                    Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
                    if (symbol != null) {
                        symbol.setName(newSymbolName, SourceType.USER_DEFINED);
                    } else {
                        api.createLabel(address, newSymbolName, true);
                    }
                    responseObserver.onNext(response.build());
                    responseObserver.onCompleted();
                } catch (InvalidInputException e) {
                    Msg.error(this, "Error setting symbol name: " + request.toString(), e);
                    responseObserver.onError(new RevaActionCancelled("Error setting symbol name: " + newSymbolName));
                } catch (DuplicateNameException e) {
                    Msg.warn(this, "Duplicate name: " + newSymbolName , e);
                    responseObserver.onError(new RevaActionCancelled("Duplicate name: " + newSymbolName));
                } catch (Exception e) {
                    Msg.error(this, "Failed to set symbol name", e);
                    responseObserver.onError(new RevaActionCancelled("Failed to set the symbol name: " + newSymbolName));
                }

                // Always at least end the transaction
                currentProgram.endTransaction(transactionId, true);
            })
            .setOnRejected(() -> {
                Status status = Status.CANCELLED.withDescription("User rejected the action");
                responseObserver.onError(status.asRuntimeException());
            })
            .build();

        this.plugin.addAction(action);
    }

    @Override
    public void getSymbol(RevaSymbolRequest request, StreamObserver<RevaSymbolResponse> responseObserver) {
        RevaSymbolResponse.Builder response = RevaSymbolResponse.newBuilder();
        Program currentProgram = this.plugin.getCurrentProgram();

        Address address = currentProgram.getAddressFactory().getAddress(request.getAddress());
        if (address != null) {
            Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
            if (symbol != null) {
                response.setName(symbol.getName(true));
                response.setAddress(symbol.getAddress().toString());

                if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                    response.setType(reva.protocol.RevaGetSymbols.SymbolType.FUNCTION);
                } else if (symbol.getSymbolType() == SymbolType.LABEL) {
                    response.setType(reva.protocol.RevaGetSymbols.SymbolType.LABEL);
                }
            }
        }

        Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
        if (function != null) {
            response.setName(function.getName(true));
            response.setAddress(function.getEntryPoint().toString());
            response.setType(reva.protocol.RevaGetSymbols.SymbolType.FUNCTION);
        }

        Data data = currentProgram.getListing().getDataContaining(address);
        if (data != null) {
            response.setName(data.getLabel());
            response.setAddress(data.getMinAddress().toString());
            response.setType(reva.protocol.RevaGetSymbols.SymbolType.DATA);
        }

        responseObserver.onNext(response.build());
        responseObserver.onCompleted();
    }
}
