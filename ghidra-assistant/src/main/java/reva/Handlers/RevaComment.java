package reva.Handlers;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
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
        Address address = plugin.addressFromAddressOrSymbol(request.getSymbolOrAddress());
        String comment = request.getComment();

        RevaSetCommentResponse response = RevaSetCommentResponse.newBuilder().build();
        // Create an action to comment
        RevaAction action = new RevaAction.Builder()
            .setLocation(address)
            .setName("Comment")
            .setDescription("Comment: " + comment)
            .setOnAccepted(() -> {
                FlatProgramAPI api = new FlatProgramAPI(plugin.getCurrentProgram());
                int transactionId = plugin.getCurrentProgram().startTransaction("Set Comment at " + address);
                api.setPlateComment(address, comment);
                plugin.getCurrentProgram().endTransaction(transactionId, true);
                responseObserver.onNext(response);
                responseObserver.onCompleted();
            })
            .setOnRejected(() -> {
                responseObserver.onError(new RevaActionCancelled("Comment rejected by user"));
            })
            .build();
        plugin.addAction(action);
    }
}
