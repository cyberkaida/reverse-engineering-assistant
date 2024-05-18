package reva.Handlers;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import reva.RevaPlugin;
import reva.Actions.RevaAction;
import reva.Actions.RevaActionCancelled;
import reva.protocol.RevaComment.RevaSetCommentRequest;
import reva.protocol.RevaComment.RevaSetCommentResponse;
import reva.protocol.RevaCommentServiceGrpc.RevaCommentServiceImplBase;

public class RevaComment extends RevaCommentServiceImplBase {
    RevaPlugin plugin;
    public RevaComment(RevaPlugin plugin) {
        super();
        this.plugin = plugin;
    }

    @Override
    public void setComment(RevaSetCommentRequest request, StreamObserver<RevaSetCommentResponse> responseObserver) {

        Program currentProgram = plugin.getCurrentProgram();
        Address address = currentProgram.getAddressFactory().getAddress(request.getAddress());
        String comment = request.getComment();
        RevaSetCommentResponse response = RevaSetCommentResponse.newBuilder().build();
        // Create an action to comment
        RevaAction action = new RevaAction.Builder()
            .setPlugin(this.plugin)
            .setLocation(address)
            .setName("Comment")
            .setDescription("Comment: " + comment)
            .setOnAccepted(() -> {
                FlatProgramAPI api = new FlatProgramAPI(currentProgram);
                int transactionId = currentProgram.startTransaction("Set Comment at " + address);
                api.setPlateComment(address, comment);
                currentProgram.endTransaction(transactionId, true);
                responseObserver.onNext(response);
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
