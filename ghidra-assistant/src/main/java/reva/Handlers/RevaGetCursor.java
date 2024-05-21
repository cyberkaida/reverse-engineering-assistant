package reva.Handlers;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import io.grpc.stub.StreamObserver;
import reva.RevaPlugin;
import reva.Actions.RevaAction;
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
        ProgramSelection selection = this.plugin.getProgramSelection();

        RevaAction action = new RevaAction.Builder()
            .setPlugin(this.plugin)
            .setName("Get cursor")
            .setDescription("Get the current cursor location")
            .setLocation(location.getAddress())
            .setOnAccepted( () -> {
                    response.setAddress(location.getAddress().toString());
                    Symbol symbol = location.getProgram()
                            .getSymbolTable()
                            .getPrimarySymbol(location.getAddress());
                    Function function = location.getProgram()
                            .getFunctionManager()
                            .getFunctionContaining(location.getAddress());
                    if (function != null) {
                        response.setFunction(
                                function.getName(true));
                    }
                    if (symbol != null) {
                        response.setSymbol(
                                symbol.getName());
                    }
                responseObserver.onNext(response.build());
                responseObserver.onCompleted();
            })
            .build();

        this.plugin.addAction(action);
        action.accept();
    }
}
