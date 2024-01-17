package reva.RevaMessageHandlers;

import java.util.List;

import com.contrastsecurity.sarif.Run;

import ghidra.util.Msg;
import reva.RevaService;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;

import java.util.ArrayList;

public abstract class RevaMessageHandler {
    RevaService service;

     /**
     * A list of all the ReVa handler types we know about.
     * 
     * If your message handler type is not in this list, it will not be dispatched correctly.
     */
    static final List<Class<? extends RevaMessageHandler>> messageHandlers;
    static {
        messageHandlers = new ArrayList<Class<? extends RevaMessageHandler>>();
        // Add all the message types we know about here
        messageHandlers.add(RevaGetDataAtAddressHandler.class);
        messageHandlers.add(RevaGetDecompilationHandler.class);
        messageHandlers.add(RevaGetFunctionCountHandler.class);
        messageHandlers.add(RevaGetDefinedFunctionListHandler.class);
    }

    public static Class<? extends RevaMessageHandler> getHandlerClass(String messageType) {
        for (Class<? extends RevaMessageHandler> type : messageHandlers) {
            Msg.trace(RevaMessageHandler.class, "Checking if " + type.getSimpleName() + " should handle " + messageType);
            if (type.getSimpleName().equals(messageType + "Handler")) {
                return type;
            }
        }
        Msg.error(RevaMessageHandler.class, "No handler found for message type " + messageType);
        throw new RuntimeException("No handler found for message type " + messageType);
    }

    public static RevaMessageHandler getHandler(String messageType, RevaService service) {
        Class<? extends RevaMessageHandler> type = getHandlerClass(messageType);
        try {
            return type.getConstructor(RevaService.class).newInstance(service);
        } catch (Exception e) {
            Msg.error(RevaMessageHandler.class, "Failed to create handler for message type " + messageType, e);
            throw new RuntimeException(e);
        }
    }

    public RevaMessageHandler(RevaService service) {
        this.service = service;
    }

    public abstract RevaMessageResponse handleMessage(RevaMessage message);
}
