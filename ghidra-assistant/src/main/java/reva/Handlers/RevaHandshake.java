package reva.Handlers;
import reva.protocol.RevaHandshakeOuterClass.*;
import io.grpc.stub.StreamObserver;
import reva.RevaPlugin;
import reva.protocol.RevaHandshakeGrpc.RevaHandshakeImplBase;

public class RevaHandshake extends RevaHandshakeImplBase {
    RevaPlugin plugin;

    public RevaHandshake(RevaPlugin plugin) {
        super();
        this.plugin = plugin;
    }

    @Override
    public void handshake(RevaHandshakeRequest request, StreamObserver<RevaHandshakeResponse> responseObserver) {
        RevaHandshakeResponse response = RevaHandshakeResponse.newBuilder().build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }
}
