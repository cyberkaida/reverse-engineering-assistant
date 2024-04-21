package reva.Handlers;
import ghidra.program.util.ProgramLocation;
import io.grpc.stub.StreamObserver;
import reva.RevaPlugin;
import reva.protocol.RevaGetCursorGrpc.RevaGetCursorImplBase;
import reva.protocol.RevaGetCursorOuterClass.RevaGetCursorRequest;
import reva.protocol.RevaGetCursorOuterClass.RevaGetCursorResponse;

public class RevaGetCursor extends RevaGetCursorImplBase {
    RevaPlugin plugin;
    public RevaGetCursor(RevaPlugin plugin) {
        super();
        this.plugin = plugin;
    }

    @Override
    public void getCursor(RevaGetCursorRequest request, StreamObserver<RevaGetCursorResponse> responseObserver) {
        RevaGetCursorResponse.Builder response = RevaGetCursorResponse.newBuilder();
        ProgramLocation location = this.plugin.getProgramLocation();
        response.setCursorAddress(location.getAddress().getUnsignedOffset());
        response.setFunction(
            location.getProgram()
                .getFunctionManager()
                .getFunctionContaining(location.getAddress())
                .getName(true)
        );
        response.setSymbol(
            location.getProgram()
                .getSymbolTable()
                .getPrimarySymbol(location.getAddress())
                .getName()
        );
        responseObserver.onNext(response.build());
        responseObserver.onCompleted();
    }
}
