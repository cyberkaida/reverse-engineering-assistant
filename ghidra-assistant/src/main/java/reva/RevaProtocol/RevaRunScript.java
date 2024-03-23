package reva.RevaProtocol;

public class RevaRunScript extends RevaMessage {
    public Boolean needs_write = false;
    public String python3_script;
    public RevaRunScript() {
        message_type = "RevaRunScript";
    }
}
