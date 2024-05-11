package reva.Handlers;
import java.util.Iterator;

import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.GlobalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import reva.RevaPlugin;
import reva.Actions.RevaAction;
import reva.Actions.RevaActionCancelled;
import reva.protocol.RevaDecompilationServiceGrpc.RevaDecompilationServiceImplBase;
import reva.protocol.RevaGetDecompilation.*;
import reva.protocol.RevaVariableOuterClass.RevaVariable;

public class RevaGetDecompilation extends RevaDecompilationServiceImplBase {
    RevaPlugin plugin;

    public RevaGetDecompilation(RevaPlugin plugin) {
        super();
        this.plugin = plugin;
    }

    @Override
    public void getDecompilation(RevaGetDecompilationRequest request,
            StreamObserver<RevaGetDecompilationResponse> responseObserver) {
        RevaGetDecompilationResponse.Builder response = RevaGetDecompilationResponse.newBuilder();

        Msg.info(this, "Getting decompilation for " + request.toString());
        TaskMonitor monitor = new TaskMonitorAdapter();

        Program currentProgram = this.plugin.getCurrentProgram();
        Function function = null;

        FlatProgramAPI api = new FlatProgramAPI(currentProgram);
        FlatDecompilerAPI decompiler = new FlatDecompilerAPI(api);

        if (request.getAddress().length() != 0) {
            Address address = currentProgram.getAddressFactory().getAddress(request.getAddress());
            function = currentProgram.getFunctionManager().getFunctionContaining(address);

            if (function == null) {
                // There was nothing there...
                response.setErrorMessage("No function found at address " + request.getAddress());
                responseObserver.onNext(response.build());
                responseObserver.onCompleted();
                return;
            }

        } else if (request.getFunction().length() != 0) {

            function = this.plugin.findFunction(request.getFunction());

            if (function == null) {
                // There was nothing there...
                response.setErrorMessage("No function found with name " + request.getFunction());
                responseObserver.onNext(response.build());
                responseObserver.onCompleted();
                return;
            }
        }

        if (function == null) {
            throw new IllegalStateException("Function was null, but we should have caught this earlier");
        }

        for (Function caller : function.getCallingFunctions(monitor)) {
            response.addIncomingCalls(caller.getName(true));
        }

        for (Function callee : function.getCalledFunctions(monitor)) {
            response.addOutgoingCalls(callee.getName(true));
        }
        response.setAddress(function.getEntryPoint().getUnsignedOffset());
        response.setFunction(function.getName(true));
        response.setFunctionSignature(function.getPrototypeString(true, true));

        // And then let's try the decompiler
        try {
            decompiler.initialize();
        } catch (Exception e) {
            // Not a problem
        }

        DecompInterface decompilerInterface = decompiler.getDecompiler();
        if (decompilerInterface != null) {
            Msg.info(this, "Using decompiler interface");
            DecompileResults decompiled = decompilerInterface.decompileFunction(function, 60, monitor);
            if (decompiled == null) {
                Boolean isThunk = function.isThunk();
                response.setErrorMessage("Failed to decompile function " + function.getName());
                if (isThunk) {
                    // If the thing is a thunk, we cannot decompile it (no implementation)
                    // and we need to tell the LLM about it so it does not try again.
                    response.setErrorMessage("Failed to decompile function " + function.getName() + " is a thunk");
                }
                responseObserver.onNext(response.build());
                responseObserver.onCompleted();
                return;
            }
            DecompiledFunction decompiledFunction = decompiled.getDecompiledFunction();
            Iterator<ClangToken> tokenIterator = decompiled.getCCodeMarkup().tokenIterator(true);
            String decompilationString = "";
            Address lastMinAddress = null;
            while (tokenIterator.hasNext()) {
                ClangToken token = tokenIterator.next();
                if (token.getMinAddress() != null) {
                    if (lastMinAddress == null || !lastMinAddress.equals(token.getMinAddress())) {
                        lastMinAddress = token.getMinAddress();
                        decompilationString += "\n/* " + lastMinAddress.toString() + " */\n";
                    }
                    decompilationString += token.toString();
                }
            }

            // response.decompilation = decompiledFunction.getC();
            response.setDecompilation(decompilationString);

            LocalSymbolMap symbolMap = decompiled.getHighFunction().getLocalSymbolMap();
            Iterator<HighSymbol> symbolIterator = symbolMap.getSymbols();
            while (symbolIterator.hasNext()) {
                HighSymbol symbol = symbolIterator.next();
                String name = symbol.getName();
                String data_type = symbol.getDataType().toString();
                String storage = symbol.getStorage().toString();
                int size = symbol.getSize();
                Msg.info(this, "Symbol: " + name + " " + data_type + " " + storage + " " + size);
                RevaVariable.Builder variable = RevaVariable.newBuilder();
                variable.setName(name);
                variable.setDataType(data_type);
                variable.setStorage(storage);
                variable.setSize(size);
                response.addVariables(variable);
            }
        } else {
            // Get the decompilation
            Msg.info(this, "Using flat decompiler");
            try {
                response.setDecompilation(decompiler.decompile(function));

            } catch (Exception e) {
                response.setErrorMessage("Failed to decompile function " + function.getName());
                Msg.error(this, "Failed to decompile function " + function.getName(), e);
            }
        }

        responseObserver.onNext(response.build());
        responseObserver.onCompleted();
    }

    @Override
    public void renameFunctionVariable(RevaRenameFunctionVariableRequest request,
            StreamObserver<RevaRenameFunctionVariableResponse> responseObserver) {
        RevaRenameFunctionVariableResponse.Builder response = RevaRenameFunctionVariableResponse.newBuilder();
        Msg.info(this, "Renaming variable " + request.getOldName() + " to " + request.getNewName() + " in function " + request.getFunctionName());
        Function function = this.plugin.findFunction(request.getFunctionName());
        if (function == null) {
            Msg.warn(this, "No function found with name " + request.getFunctionName() + " in " + plugin.getCurrentProgram().getName());
            responseObserver.onError(new RevaActionCancelled("No function found with name " + request.getFunctionName()));
            return;
        }


        FlatProgramAPI api = new FlatProgramAPI(plugin.getCurrentProgram());
        FlatDecompilerAPI decompiler = new FlatDecompilerAPI(api);

        // Let's get the decompilation of the function, then get the high variables
        // and rename those!
        try {
            decompiler.initialize();
        } catch (Exception e) {
            String error = "Failed to initialize decompiler: " + e.getMessage();
            responseObserver.onError(new RevaActionCancelled(error));
            return;
        }

        TaskMonitor monitor = new TaskMonitorAdapter();
        DecompInterface decompilerInterface =  decompiler.getDecompiler();
        DecompileResults decompiled = decompilerInterface.decompileFunction(function, 60, monitor);
        if (decompiled == null) {
            String error = "Failed to decompile function " + function.getName(true);
            responseObserver.onError(new RevaActionCancelled(error));
            return;
        }

        DecompiledFunction decompiledFunction = decompiled.getDecompiledFunction();
        GlobalSymbolMap globalMap = decompiled.getHighFunction().getGlobalSymbolMap();
        LocalSymbolMap localMap = decompiled.getHighFunction().getLocalSymbolMap();


        RevaAction action = new RevaAction.Builder()
            .setLocation(function.getEntryPoint())
            .setName("Rename Variable")
            .setDescription("Rename variable " + request.getOldName() + " to " + request.getNewName())
            .setOnAccepted(() -> {
                Iterator<HighSymbol> highSymbolIterator = localMap.getSymbols();
                while (highSymbolIterator.hasNext()) {
                    HighSymbol highSymbol = highSymbolIterator.next();
                    if (highSymbol.getName().equals(request.getOldName())) {
                        try {
                            int transactionId = plugin.getCurrentProgram().startTransaction("Rename Variable");
                            HighFunctionDBUtil.updateDBVariable(highSymbol, request.getNewName(), null, SourceType.ANALYSIS);
                            plugin.getCurrentProgram().endTransaction(transactionId, true);
                            break;
                        } catch (DuplicateNameException | InvalidInputException e) {
                            String error = "Failed to rename variable: " + e.getMessage();
                            Status status = Status.ALREADY_EXISTS.withDescription(error);
                            responseObserver.onError(status.asRuntimeException());
                            return;
                        }
                    }
                }

                // Now for the globals
                Iterator<HighSymbol> globalSymbolIterator = globalMap.getSymbols();
                while (globalSymbolIterator.hasNext()) {
                    HighSymbol highSymbol = globalSymbolIterator.next();
                    if (highSymbol.getName().equals(request.getOldName())) {
                        try {
                            int transactionId = plugin.getCurrentProgram().startTransaction("Rename Variable");
                            HighFunctionDBUtil.updateDBVariable(highSymbol, request.getNewName(), null, SourceType.ANALYSIS);
                            plugin.getCurrentProgram().endTransaction(transactionId, true);
                            break;
                        } catch (DuplicateNameException | InvalidInputException e) {
                            String error = "Failed to rename variable: " + e.getMessage();
                            Status status = Status.ALREADY_EXISTS.withDescription(error);
                            responseObserver.onError(status.asRuntimeException());
                            return;
                        }
                    }
                }

                responseObserver.onNext(response.build());
                responseObserver.onCompleted();
            })
            .setOnRejected(() -> {
                    Status status = Status.CANCELLED.withDescription("User rejected the action");

                    responseObserver.onError(status.asRuntimeException());
                }
            )
            .build();

        this.plugin.addAction(action);
    }
}
