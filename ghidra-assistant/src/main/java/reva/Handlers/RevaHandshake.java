package reva.Handlers;
import reva.protocol.RevaHandshakeOuterClass.*;
import ghidra.util.Msg;
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
        String hostname = request.getInferenceHostname();
        int port = request.getInferencePort();

        Msg.info(this, String.format("Received handshake request from %s:%d", hostname, port));
        plugin.registerInference(hostname, port);

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }
}
