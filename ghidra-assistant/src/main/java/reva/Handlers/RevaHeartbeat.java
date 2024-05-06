package reva.Handlers;

import reva.RevaPlugin;
import reva.protocol.RevaHeartbeatGrpc.RevaHeartbeatImplBase;
import reva.protocol.RevaHeartbeatOuterClass.RevaHeartbeatRequest;
import reva.protocol.RevaHeartbeatOuterClass.RevaHeartbeatResponse;
import io.grpc.stub.StreamObserver;

public class RevaHeartbeat extends RevaHeartbeatImplBase {
    RevaPlugin plugin;
    public RevaHeartbeat(RevaPlugin plugin) {
        super();
        this.plugin = plugin;
    }

    @Override
    public void heartbeat(RevaHeartbeatRequest request, StreamObserver<RevaHeartbeatResponse> responseObserver) {
        RevaHeartbeatResponse.Builder response = RevaHeartbeatResponse.newBuilder();

        response.setExtensionHostname(plugin.getExtensionHostname());
        response.setExtensionPort(plugin.getExtensionPort());
        response.setInferenceHostname(plugin.getInferenceHostname());
        response.setInferencePort(plugin.getInferencePort());
        response.setProjectName(plugin.getTool().getProject().getName());

        responseObserver.onNext(response.build());
        responseObserver.onCompleted();
    }
}
