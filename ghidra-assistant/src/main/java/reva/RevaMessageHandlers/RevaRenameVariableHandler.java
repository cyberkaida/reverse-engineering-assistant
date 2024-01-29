package reva.RevaMessageHandlers;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import reva.RevaService;
import reva.RevaProtocol.RevaGetFunctionCount;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;
import reva.RevaProtocol.RevaRenameVariable;
import reva.RevaProtocol.RevaRenameVariableResponse;

public class RevaRenameVariableHandler extends RevaMessageHandler {
    public RevaRenameVariableHandler(RevaService service) {
        super(service);
    }

    @Override
    public RevaMessageResponse handleMessage(RevaMessage message) {
        RevaRenameVariable request = (RevaRenameVariable) message;
        RevaRenameVariableResponse response = new RevaRenameVariableResponse(request);
        Msg.info(this, "Renaming variable " + request.variable.name + " to " + request.new_name + " in function " + request.function_name);
        Function function = this.findFunction(request.function_name);
        if (function == null) {
            Msg.warn(this, "No function found with name " + request.function_name + " in " + service.currentProgram.getName());
            response.error_message = "No function found with name " + request.function_name;
            return response;
        }

        // Now we have the function, let's get its local variables
        Variable[] variables = function.getAllVariables();
        Boolean renamed = false;
        for (Variable variable : variables) {
            if (variable.getName().equals(request.variable.name)) {
                try {
                    variable.setName(request.new_name, SourceType.ANALYSIS);
                    Msg.info(this, "Renamed variable " + request.variable.name + " to " + request.new_name + " in function " + function.getName(true));
                } catch (DuplicateNameException | InvalidInputException e) {
                    response.error_message = "Failed to rename variable: " + e.getMessage();
                    return response;
                }
                return response;
            }
        }

        if (!renamed) {
            response.error_message = "No variable found with name " + request.variable.name + " in function " + function.getName(true);
            return response;
        }

        return null;
    }
}
