package reva.RevaProtocol;

public class RevaGetDefinedFunctionList extends RevaMessage {
    public int page;
    public int page_size;
    public RevaGetDefinedFunctionList() {
        message_type = "RevaGetDefinedFunctionList";
    }
}
