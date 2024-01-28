package reva.RevaProtocol;

/**
 * Request the decompilation for a given function
 * either by address or by name
 */
public class RevaGetDecompilation extends RevaMessage {
    public String address;
    public String function;

    public RevaGetDecompilation() {
        message_type = "RevaGetDecompilation";
    }
}
