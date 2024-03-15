package reva;

import org.apache.commons.lang.NotImplementedException;

import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import reva.RevaMessageHandlers.RevaMessageHandler;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;

import ghidra.program.model.address.Address;
import ghidra.program.model.correlate.Block;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

import java.io.IOException;
import java.nio.file.*;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import java.net.http.HttpClient;
import java.net.URI;
import java.util.ArrayList;

/**
 * This class provides services to the ReVa tool
 * (that runs outside of Ghidra). It will run a background
 * thread that will communicate with the ReVa tool.
 *
 * TODO: Should this be a GTask or something else?
 */
public class RevaService extends Task {

    public Boolean connected = false;

    class RevaServerException extends Exception {
        public RevaServerException(String message) {
            super(message);
        }

        public RevaServerException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public Program currentProgram;
    /**
     * The path to the ReVa project directory for the program represented by
     * {@link currentProgram}.
     */
    private Path revaProjectPath;

    private HttpClient revaClient;
    private URI revaServerBase;;

    // At first we will implement a simple directory based thing.
    public static final Path REVA_CACHE_DIR = Paths.get(System.getProperty("user.home"), ".cache",
            "reverse-engineering-assistant");

    /**
     * A queue of messages to send to ReVa.
     */
    private BlockingQueue<RevaCallbackHandler> toRevaQueue = new LinkedBlockingQueue<RevaCallbackHandler>();
    private BlockingQueue<RevaCallbackHandler> waitingForResponseFromReva = new LinkedBlockingQueue<RevaCallbackHandler>();
    /**
     * A queue of messages received from ReVa.
     */
    private BlockingQueue<RevaCallbackHandler> toToolQueue = new LinkedBlockingQueue<RevaCallbackHandler>();
    private BlockingQueue<RevaCallbackHandler> waitingForResponseFromTool = new LinkedBlockingQueue<RevaCallbackHandler>();

    /**
     * Communicate synchronously with ReVa.
     *
     * @apiNote If no response is received, we will wait _forever_.
     * @param message The message to send
     * @return RevaMessage The response from ReVa
     */
    public RevaMessageResponse communicateToReva(RevaMessage message) {
        RevaCallbackHandler handler = new RevaCallbackHandler(message);
        toRevaQueue.add(handler);
        RevaMessageResponse response = handler.waitForResponse();
        waitingForResponseFromReva.remove(handler);
        return response;
    }

    /**
     * Send a message to ReVa. Don't expect a response.
     *
     * @param message the message to send
     */
    public void sendToReva(RevaMessage message) {
        RevaCallbackHandler handler = new RevaCallbackHandler(message);
        Msg.debug(this, "Queuing message for ReVa: " + message.toJson());
        toRevaQueue.add(handler);
    }

    /**
     * Get the next message from ReVa.
     *
     * @return the next message from ReVa, or null if there are no messages
     * @throws RevaServerException if there is a problem communicating with ReVa
     */
    private RevaMessage getMessageFromServer() throws RevaServerException {
        URI endpoint = revaServerBase.resolve("/project/" + currentProgram.getName() + "/message");
        Msg.trace(this, "Getting message from " + endpoint.toString());
        try {
            var request = java.net.http.HttpRequest.newBuilder()
                    .uri(endpoint)
                    .header("Content-Type", "application/json")
                    .GET()
                    .build();
            var response = revaClient.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 204) {
                Msg.trace(this, "No message from ReVa");
                return null;
            } else if (response.statusCode() != 200) {
                throw new RevaServerException("ReVa server returned status code " + response.statusCode());
            }
            var message = RevaMessage.fromJson(response.body());
            Msg.info(this, "Got message: " + message.toJson());
            return message;
        } catch (Exception e) {
            throw new RevaServerException("Exception while communicating with ReVa", e);
        }
    }

    private RevaMessageResponse getResponseFromServer(String messageId) {
        URI endpoint = revaServerBase.resolve("/project/" + currentProgram.getName() + "/message/" + messageId);
        Msg.trace(this, "Getting response from " + endpoint.toString());
        try {
            var request = java.net.http.HttpRequest.newBuilder()
                    .uri(endpoint)
                    .header("Content-Type", "application/json")
                    .GET()
                    .build();
            var response = revaClient.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 204) {
                Msg.trace(this, "No response from ReVa");
                return null;
            } else if (response.statusCode() != 200) {
                throw new RevaServerException("ReVa server returned status code " + response.statusCode());
            }
            var message = RevaMessage.fromJson(response.body());
            Msg.info(this, "Got response: " + message.toJson());
            return (RevaMessageResponse) message;
        } catch (Exception e) {
            throw new RuntimeException("Exception while communicating with ReVa", e);
        }
    }

    /**
     * Send a message to ReVa.
     *
     * @param message the message to send
     * @throws RevaServerException if there is a problem communicating with ReVa
     */
    private void sendMessageToServer(RevaMessage message) throws RevaServerException {
        // Use a HTTP request to talk to the reva-server
        // on localhost:44916.
        // We want to send the JSON message to the endpoint
        // /project/<project_name>/task
        // We'll hardcode the project to "wide" for now

        URI endpoint = revaServerBase.resolve("/project/" + currentProgram.getName() + "/message");

        Msg.info(this, "Sending message to " + endpoint.toString() + ": " + message.toJson());
        try {
            var request = java.net.http.HttpRequest.newBuilder()
                    .uri(endpoint)
                    .header("Content-Type", "application/json")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(message.toJson()))
                    .build();
            var response = revaClient.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new RevaServerException("ReVa server returned status code " + response.statusCode());
            }
        } catch (Exception e) {
            Msg.error(this, "Exception while comminucating with ReVa", e);
            throw new RevaServerException("Exception while communicating with ReVa", e);
        }
    }

    private void sendResponseToReva(RevaMessageResponse response) throws RevaServerException {
        // Use a HTTP request to talk to the reva-server
        // on localhost:44916.
        // We want to send the JSON message to the endpoint
        // /project/<project_name>/message/<message_id>

        URI endpoint = revaServerBase.resolve("/project/" + currentProgram.getName() + "/message/" + response.message_id);

        Msg.info(this, "Sending response to " + endpoint.toString() + ": " + response.toJson());
        try {
            var request = java.net.http.HttpRequest.newBuilder()
                    .uri(endpoint)
                    .header("Content-Type", "application/json")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(response.toJson()))
                    .build();
            var http_response = revaClient.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (http_response.statusCode() != 200) {
                throw new RevaServerException("ReVa server returned status code " + http_response.statusCode());
            }
        } catch (Exception e) {
            Msg.error(this, "Exception while comminucating with ReVa", e);
            throw new RevaServerException("Exception while communicating with ReVa", e);
        }
    }

    /**
     * Create a new RevaService.
     *
     * @param program the program to provide services for
     */
    public RevaService(Program program) {
        super("RevaService");
        this.currentProgram = program;
        // Note, Program can be null here.
        // this.revaProjectPath =
        // REVA_CACHE_DIR.resolve("projects").resolve(program.getName());

        this.revaClient = HttpClient.newHttpClient();
        try {
            this.revaServerBase = new URI("http://localhost:44916");
        } catch (Exception e) {
            throw new RuntimeException("Malformed URI", e);
        }
    }

    /**
     * Run the main communications thread. This will make HTTP requests to the ReVa
     * tool.
     */
    public void run(TaskMonitor monitor) {
        // Monitor the to-tool directory for messages from ReVa.

        connected = false;
        Msg.info(this, "ReVa communications thread starting");
        while (!monitor.isCancelled()) {
            // This is super verbose, but useful for debugging deadlocks
            // Msg.info(this, "Communicating!");
            try {

                {
                    // Let's submit any responses we might have
                    RevaCallbackHandler handler = waitingForResponseFromTool.poll();
                    if (handler != null) {
                        if (handler.hasResponse()) {
                            RevaMessageResponse response = handler.getResponse();
                            sendResponseToReva(response);
                            Msg.info(this, "Sent response to ReVa: " + response.toJson());
                        } else {
                            waitingForResponseFromTool.add(handler);
                        }
                    }
                }

                // Now see if there is a message waiting for us
                RevaMessage message = getMessageFromServer();
                if (message != null) {
                    RevaCallbackHandler callback_handler = new RevaCallbackHandler(message);
                    toToolQueue.add(callback_handler);
                    Msg.info(this, "Got message from ReVa and queued: " + message.toJson());
                }

                {
                    // Now query the things we're waiting for ReVa server to complete
                    RevaCallbackHandler handler = waitingForResponseFromReva.poll();
                    if (handler != null) {
                        RevaMessageResponse response = getResponseFromServer(handler.message.message_id.toString());
                        if (response != null) {
                            handler.submitResponse(response);
                            Msg.info(this, "Got response from ReVa: " + response.toJson());
                        } else {
                            // Still waiting
                            waitingForResponseFromReva.add(handler);
                        }
                    }
                }

                // Now let's see if there is a message for us to send
                RevaCallbackHandler toReva = toRevaQueue.poll();
                if (toReva != null) {
                    sendMessageToServer(toReva.message);
                    waitingForResponseFromReva.add(toReva);
                }

                {
                    // Pop something off the waitingForTool queue and do some work
                    RevaCallbackHandler callbackHandler = toToolQueue.poll();
                    if (callbackHandler != null) {
                        int transaction = currentProgram.startTransaction("ReVa: " + callbackHandler.message.message_type);
                        Msg.info(this, "Got work to do! " + callbackHandler.message.toJson());
                        // TODO: Move this to a Task
                        RevaMessageHandler handler = RevaMessageHandler.getHandler(message.message_type, this);
                        RevaMessageResponse response = handler.handleMessage(message);
                        Msg.info(this, "Work done!: " + response.toJson());
                        callbackHandler.submitResponse(response);
                        // We took this off the queue, so put it back on now it's done
                        // TODO: Need another queue?
                        waitingForResponseFromTool.add(callbackHandler);
                        currentProgram.endTransaction(transaction, true);
                    } else {
                        Thread.sleep(100);
                    }
                }

            } catch (RevaServerException e) {
                try {
                    if (connected) {
                        connected = false;
                        Msg.error(this, "Exception while communicating with ReVa. Lost connection.", e);
                    }
                    Thread.sleep(5000);
                } catch (InterruptedException e1) {
                    Msg.error(this, "Interrupted while waiting to retry", e1);
                    monitor.cancel();
                }
            } catch (InterruptedException e) {
                Msg.error(this, "Interrupted while waiting for message", e);
            }
        }
    }
}
