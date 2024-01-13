package reva.RevaProtocol;
import java.util.UUID;
import com.google.gson.Gson;

import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.List;

/**
 * Base class for all messages sent between the inference side and
 * the reverse engineering tool. When dealing with a message, you
 * should always use the subclass, not this base class.
 * 
 * This class provides a way to serialize and deserialize messages
 * to and from JSON, see {@link fromJson} and {@link toJson}.
 */
public class RevaMessage {

    /**
     * Thrown when there is a problem parsing a RevaMessage from JSON.
     */
    public static class RevaMessageParseException extends Exception {
        public RevaMessageParseException(String message) {
            super(message);
        }

        public RevaMessageParseException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public String message_type = "RevaMessage";
    UUID messageId = UUID.randomUUID();

    /**
     * A list of all the ReVa message types we know about.
     * This is used to dispatch to the correct subclass in {@link fromJson}.
     * 
     * If your message type is not in this list, it will not be deserialized correctly.
     */
    static final List<Class<? extends RevaMessage>> messageTypes;
    static {
        messageTypes = new ArrayList<Class<? extends RevaMessage>>();
        // Add all the message types we know about here
        messageTypes.add(RevaHeartbeat.class);
        messageTypes.add(RevaHeartbeatResponse.class);
    }



    /**
     * Given a JSON string, deserialize it into a specific subclass of RevaMessage.
     * 
     * This uses the {@link messageType} field of the JSON to determine which subclass to deserialize into
     * (see {@link messageTypes}).
     * 
     * @param json the JSON string to deserialize
     * @return the deserialized message, as a subclass of RevaMessage
     */
    public static RevaMessage fromJson(String json) throws RevaMessageParseException {
        Gson gson = new Gson();
        // Here we must dispatch to the correct subclass

        // First we'll turn it into a generic message
        RevaMessage generic = gson.fromJson(json, RevaMessage.class);
        Msg.trace(RevaMessage.class, "Parsing message type: " + generic.message_type + " from JSON: " + json);
        // Then we'll find the correct subclass
        for (Class<? extends RevaMessage> type : messageTypes) {

            // TODO: Is there a better way to get this now that
            // the message_type field is not static?
            if (type.getSimpleName().equals(generic.message_type)) {
                Msg.trace(RevaMessage.class, "Found message class: " + type.getName());
                // And then we'll turn it into the correct subclass
                return gson.fromJson(json, type);
            }
        }

        throw new RevaMessageParseException("Unknown message type: " + generic.message_type);
    }

    public String toJson() {
        Gson gson = new Gson();
        return gson.toJson(this);
    }
}
