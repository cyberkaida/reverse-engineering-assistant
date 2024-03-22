package reva.RevaProtocol;

public class RevaGetImportedLibrariesList extends RevaMessage {
    public int page;
    public int page_size;
    public RevaGetImportedLibrariesList() {
        message_type = "RevaGetImportedLibrariesList";
    }
}
