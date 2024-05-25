package reva.Handlers;

import reva.protocol.RevaBookmarkOuterClass.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import reva.RevaPlugin;
import reva.Actions.RevaAction;
import reva.protocol.RevaBookmarkGrpc.RevaBookmarkImplBase;;

public class RevaBookmarks extends RevaBookmarkImplBase {
    RevaPlugin plugin;

    public RevaBookmarks(RevaPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public void addBookmark(RevaAddBookmarkRequest request, StreamObserver<RevaAddBookmarkResponse> responseObserver) {
        Program program = plugin.getCurrentProgram();
        BookmarkManager bookmarkManager = program.getBookmarkManager();
        Address address = program.getAddressFactory().getAddress(request.getAddress());

        RevaAddBookmarkResponse.Builder response = RevaAddBookmarkResponse.newBuilder();

        RevaAction action = new RevaAction.Builder()
            .setPlugin(plugin)
            .setName("Set bookmark")
            .setDescription(request.getDescription())
            .setLocation(address)
            .setOnAccepted(() -> {
                int transactionId = program.startTransaction("Set bookmark");
                bookmarkManager.setBookmark(address, BookmarkType.ANALYSIS, request.getCategory(), request.getDescription());
                program.endTransaction(transactionId, true);
                responseObserver.onNext(response.build());
                responseObserver.onCompleted();
            })
            .setOnRejected(() -> {
                Msg.warn(this, "User rejected the action");
                Status status = Status.CANCELLED.withDescription("User rejected the action");
                responseObserver.onError(status.asRuntimeException());
            })
            .build();

        plugin.addAction(action);
    }

    @Override
    public void getBookmarks(RevaGetBookmarksRequest request,
            StreamObserver<RevaGetbookmarksResponse> responseObserver) {
        Program program = plugin.getCurrentProgram();
        BookmarkManager bookmarkManager = program.getBookmarkManager();

        RevaAction action = new RevaAction.Builder()
            .setPlugin(plugin)
            .setName("Get bookmarks")
            .setDescription("Get all bookmarks in the program")
            .setOnAccepted(() -> {
                bookmarkManager.getBookmarksIterator().forEachRemaining(bookmark -> {
                    RevaGetbookmarksResponse.Builder response = RevaGetbookmarksResponse.newBuilder();
                    response
                        .setAddress(bookmark.getAddress().toString())
                        .setCategory(bookmark.getCategory())
                        .setDescription(bookmark.getComment());
                    responseObserver.onNext(response.build());
                });

                responseObserver.onCompleted();
            })
            .setOnRejected(() -> {
                Msg.warn(this, "User rejected the action");
                Status status = Status.CANCELLED.withDescription("User rejected the action");
                responseObserver.onError(status.asRuntimeException());
            })
            .build();
        plugin.addAction(action);
        action.accept(); // Always get bookmarks, this does not modify the database
    }



}
