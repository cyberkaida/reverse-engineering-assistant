package reva.RevaProtocol;

public class RevaRenameVariable extends RevaMessage {
    public RevaVariable variable;
    public String new_name;
    public String function_name;

    public RevaRenameVariable(RevaVariable variable, String new_name, String function_name) {
        message_type = "RevaRenameVariable";
        this.variable = variable;
        this.new_name = new_name;
        this.function_name = function_name;
    }
}
