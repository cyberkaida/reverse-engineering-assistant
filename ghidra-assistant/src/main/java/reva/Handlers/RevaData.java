package reva.Handlers;

import io.grpc.Status;

import com.google.protobuf.ByteString;

import ghidra.app.services.DataTypeQueryService;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.CancelledException;
import io.grpc.stub.StreamObserver;
import reva.RevaPlugin;
import reva.Actions.RevaAction;
import reva.protocol.RevaData.RevaDataListRequest;
import reva.protocol.RevaData.RevaDataListResponse;
import reva.protocol.RevaData.RevaGetDataAtAddressRequest;
import reva.protocol.RevaData.RevaGetDataAtAddressResponse;
import reva.protocol.RevaData.RevaSetGlobalDataTypeRequest;
import reva.protocol.RevaData.RevaSetGlobalDataTypeResponse;
import reva.protocol.RevaData.RevaStringListRequest;
import reva.protocol.RevaData.RevaStringListResponse;
import reva.protocol.RevaDataServiceGrpc.RevaDataServiceImplBase;

public class RevaData extends RevaDataServiceImplBase {
    RevaPlugin plugin;

    public RevaData(RevaPlugin plugin) {
        super();
        this.plugin = plugin;
    }

    @Override
    public void getDataAtAddress(RevaGetDataAtAddressRequest request,
            StreamObserver<RevaGetDataAtAddressResponse> responseObserver) {
        Program currentProgram = this.plugin.getCurrentProgram();
        RevaGetDataAtAddressResponse.Builder response = RevaGetDataAtAddressResponse.newBuilder();

        Address address = null;
        if (request.getAddress() != null) {
            address = currentProgram.getAddressFactory().getAddress(request.getAddress());
        } else if (request.getSymbol() != null) {
            SymbolIterator symbolIterator = currentProgram.getSymbolTable().getSymbols(request.getSymbol());
            if (symbolIterator.hasNext()) {
                address = symbolIterator.next().getAddress();
            }

        } else {
            Status status = Status.INVALID_ARGUMENT.withDescription("No address or symbol provided");
            responseObserver.onError(status.asRuntimeException());
            return;
        }

        if (address == null) {
            Status status = Status.NOT_FOUND.withDescription("Address or symbol not found");
            responseObserver.onError(status.asRuntimeException());
            return;
        }

        final Address requestedAddress = address;

        RevaAction action = new RevaAction.Builder()
                .setPlugin(this.plugin)
                .setLocation(requestedAddress)
                .setDescription(String.format("Get data at %s - %d bytes", address.toString(), request.getSize()))
                .setName("Get Data")
                .setOnAccepted(() -> {
                    response.setAddress(requestedAddress.toString());
                    // Let's get the symbol if there is one
                    Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(requestedAddress);
                    if (symbol != null) {
                        response.setSymbol(symbol.getName());
                    }
                    // Let's get the bytes
                    if (request.getSize() > 0) {
                        byte[] bytes = new byte[(int)request.getSize()];
                        try {
                            currentProgram.getMemory().getBytes(requestedAddress, bytes);
                            response.setData(ByteString.copyFrom(bytes));
                        } catch (MemoryAccessException e) {
                            Msg.error(this, "Error reading memory at " + requestedAddress.toString());
                            Status status = Status.INTERNAL.withDescription("Error reading memory");
                            responseObserver.onError(status.asRuntimeException());
                            return;
                        }
                    }

                    Data data = currentProgram.getListing().getDataContaining(requestedAddress);
                    if (data != null) {
                        response.setAddress(data.getAddress().toString());
                        response.setType(data.getDataType().getName());
                        response.setSize(data.getLength());
                        try {
                            if (response.getData() == null) {
                                // If we didn't get the data above
                                byte b[] = data.getBytes();
                                if (b == null) {
                                    // If the data has no bytes, let's try to get between this and the next thing
                                    Data nextData = currentProgram.getListing().getDataAfter(data.getMaxAddress());
                                    int size = (int)nextData.getMinAddress().subtract(data.getMinAddress());
                                    Msg.info(this, String.format("Reading %d bytes from %s", size, data.getMinAddress()));
                                    b = new byte[size];
                                    currentProgram.getMemory().getBytes(data.getMinAddress(), b);
                                }
                                response.setData(ByteString.copyFrom(b));
                            }
                        } catch (MemoryAccessException e) {
                            Msg.error(this, "Error reading memory at " + requestedAddress.toString());
                            Status status = Status.INTERNAL.withDescription("Error reading memory");
                            responseObserver.onError(status.asRuntimeException());
                            return;
                        }

                        // If it is a data type, let's get the references
                        for (Reference reference : data.getReferencesFrom()) {
                            response.addOutgoingReferences(reference.getFromAddress().toString());
                        }

                        data.getReferenceIteratorTo().forEach(
                                reference -> response.addIncomingReferences(reference.getFromAddress().toString()));
                    }

                    responseObserver.onNext(response.build());
                    responseObserver.onCompleted();
                })
                .setOnRejected(() -> {
                    Status status = Status.CANCELLED.withDescription("User rejected the action");
                    responseObserver.onError(status.asRuntimeException());
                })
                .build();

        this.plugin.addAction(action);
        action.accept(); // Always accept getData
    }

    @Override
    public void getListData(RevaDataListRequest request, StreamObserver<RevaDataListResponse> responseObserver) {
        Program currentProgram = this.plugin.getCurrentProgram();

        RevaAction action = new RevaAction.Builder()
                .setPlugin(this.plugin)
                .setDescription("Get defined data list")
                .setName("Get Data List")
                .setOnAccepted(() -> {
                    currentProgram.getListing().getData(true).forEach(
                            data -> {
                                RevaDataListResponse.Builder response = RevaDataListResponse.newBuilder();
                                response.setAddress(data.getAddress().toString());
                                response.setType(data.getDataType().getName());

                                // Now for references
                                for (Reference reference : data.getReferencesFrom()) {
                                    response.addOutgoingReferences(reference.getFromAddress().toString());
                                }

                                data.getReferenceIteratorTo().forEach(
                                        reference -> response
                                                .addIncomingReferences(reference.getFromAddress().toString()));

                                Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(data.getAddress());
                                if (symbol != null) {
                                    response.setSymbol(symbol.getName());
                                }

                                responseObserver.onNext(response.build());
                            });

                    responseObserver.onCompleted();
                })
                .setOnRejected(() -> {
                    Status status = Status.CANCELLED.withDescription("User rejected the action");
                    responseObserver.onError(status.asRuntimeException());
                })
                .build();

        this.plugin.addAction(action);
        action.accept(); // Always accept getListData
    }

    @Override
    public void getStringList(RevaStringListRequest request, StreamObserver<RevaStringListResponse> responseObserver) {
        Program currentProgram = this.plugin.getCurrentProgram();

        RevaAction action = new RevaAction.Builder()
                .setPlugin(this.plugin)
                .setDescription("Get strings")
                .setName("Get Strings")
                .setOnAccepted(() -> {
                    currentProgram.getListing().getData(true).forEach(
                            data -> {
                                if (data.getDataType().getName().equals("string")) {
                                    RevaStringListResponse.Builder response = RevaStringListResponse.newBuilder();
                                    response.setAddress(data.getAddress().toString());
                                    response.setValue(data.getValue().toString());
                                    Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(data.getAddress());
                                    if (symbol != null) {
                                        response.setSymbol(symbol.getName());
                                    }

                                    // References
                                    for (Reference reference : data.getReferencesFrom()) {
                                        response.addOutgoingReferences(reference.getFromAddress().toString());
                                    }

                                    data.getReferenceIteratorTo().forEach(
                                            reference -> response
                                                    .addIncomingReferences(reference.getFromAddress().toString()));

                                    responseObserver.onNext(response.build());
                                }
                            });
                })
                .setOnRejected(() -> {
                    Status status = Status.CANCELLED.withDescription("User rejected the action");
                    responseObserver.onError(status.asRuntimeException());
                })
                .build();

        this.plugin.addAction(action);
        action.accept(); // Always accept getStringList

        responseObserver.onCompleted();
    }

    @Override
    public void setGlobalDataType(RevaSetGlobalDataTypeRequest request,
            StreamObserver<RevaSetGlobalDataTypeResponse> responseObserver) {
        Program currentProgram = this.plugin.getCurrentProgram();
        RevaSetGlobalDataTypeResponse.Builder response = RevaSetGlobalDataTypeResponse.newBuilder();
        Address address = currentProgram.getAddressFactory().getAddress(request.getAddress());
        DataTypeQueryService dataTypeQueryService = this.plugin.getTool().getService(DataTypeQueryService.class);
        DataTypeParser dataTypeParser = new DataTypeParser(dataTypeQueryService, AllowedDataTypes.STRINGS_AND_FIXED_LENGTH);

        RevaAction action = new RevaAction.Builder()
                .setPlugin(this.plugin)
                .setDescription(String.format("Set global data type to %s", request.getDataType()))
                .setName("Set Global Data Type")
                .setLocation(address)
                .setOnAccepted(() -> {
                    // First get the new data type
                    DataType dataType;
                    try {
                        dataType = dataTypeParser.parse(request.getDataType());
                    } catch (InvalidDataTypeException | CancelledException e) {
                        String error = "Failed to parse data type: " + e.getMessage();
                        Status status = Status.INVALID_ARGUMENT.withDescription(error);
                        responseObserver.onError(status.asRuntimeException());
                        return;
                    }

                    int transactionId = currentProgram.startTransaction("Set Global Data Type");
                    Data data = currentProgram.getListing().getDataAt(address);
                    if (data != null) {
                        currentProgram.getListing().clearCodeUnits(data.getMinAddress(), data.getMaxAddress(), false);
                    }


                    // We'll create the data
                    try {
                        data = currentProgram.getListing().createData(address, dataType);
                        currentProgram.endTransaction(transactionId, true);
                        responseObserver.onNext(response.build());
                    } catch (CodeUnitInsertionException e) {
                        currentProgram.endTransaction(transactionId, false);
                        String error = "Failed to create data: " + e.getMessage();
                        Status status = Status.INTERNAL.withDescription(error);
                        responseObserver.onError(status.asRuntimeException());
                    }
                    responseObserver.onCompleted();
                })
                .setOnRejected(() -> {
                    Status status = Status.CANCELLED.withDescription("User rejected the action");
                    responseObserver.onError(status.asRuntimeException());
                })
                .build();
        plugin.addAction(action);
    }




}
