package reva.Handlers;

import reva.protocol.RevaHandshakeOuterClass.*;
import ghidra.util.Msg;
import io.grpc.stub.StreamObserver;
import reva.protocol.RevaHandshakeGrpc.RevaHandshakeImplBase;

public class RevaHeartbeat extends RevaHandshakeImplBase {
    public RevaHeartbeat() {
        super();
    }

	@Override
	public void handshake(RevaHandshakeRequest request, StreamObserver<RevaHandshakeResponse> responseObserver) {
        RevaHandshakeResponse response = RevaHandshakeResponse.newBuilder().build();
        responseObserver.onNext(response);
		responseObserver.onCompleted();
        Msg.trace(this, "Heartbeat complete");
	}
}
