package reva.Handlers;
import reva.protocol.RevaReferences.*;

import io.grpc.Status;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import io.grpc.stub.StreamObserver;
import reva.RevaPlugin;
import reva.Actions.RevaAction;
import reva.protocol.RevaReferenceServiceGrpc.RevaReferenceServiceImplBase;;


public class RevaReferences extends RevaReferenceServiceImplBase {
    RevaPlugin plugin;

    public RevaReferences(RevaPlugin plugin) {
        super();
        this.plugin = plugin;
    }

    @Override
    public void getReferences(RevaGetReferencesRequest request,
            StreamObserver<RevaGetReferencesResponse> responseObserver) {
        RevaGetReferencesResponse.Builder response = RevaGetReferencesResponse.newBuilder();
        Program currentProgram = this.plugin.getCurrentProgram();

        if (request.getAddress() == null) {
            Status status = Status.INVALID_ARGUMENT.withDescription("Address is required");
            responseObserver.onError(status.asRuntimeException());
            return;
        }

        Address address = currentProgram.getAddressFactory().getAddress(request.getAddress());

        RevaAction action = new RevaAction.Builder()
                .setName("Get References")
                .setDescription("Get references to/from a location")
                .setLocation(address)
                .setPlugin(plugin)
                .setOnAccepted(() -> {
                    currentProgram.getReferenceManager().getReferencesTo(address).forEach(ref -> {
                        response.addIncomingReferences(ref.getFromAddress().toString());
                    });

                    for (Reference ref : currentProgram.getReferenceManager().getReferencesFrom(address)) {
                        response.addOutgoingReferences(ref.getToAddress().toString());
                    }
                    responseObserver.onNext(response.build());
                    responseObserver.onCompleted();
                }).build();

        this.plugin.addAction(action);
        action.accept();
    }


}
