package reva;

import org.apache.commons.lang.NotImplementedException;

import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import reva.RevaProtocol.RevaMessage;
import ghidra.program.model.address.Address;
import ghidra.program.model.correlate.Block;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

import java.io.IOException;
import java.nio.file.*;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * This class provides services to the ReVa tool
 * (that runs outside of Ghidra). It will run a background
 * thread that will communicate with the ReVa tool.
 * 
 * TODO: Should this be a GTask or something else?
 */
public class RevaService extends Task {

    private Program currentProgram;
    /**
     * The path to the ReVa project directory for the program represented by {@link currentProgram}.
     */
    private Path revaProjectPath;


    // At first we will implement a simple directory based thing.
    public static final Path REVA_CACHE_DIR = Paths.get(System.getProperty("user.home"), ".cache", "reverse-engineering-assistant");

    /**
     * A queue of messages to send to ReVa.
     */
    private BlockingQueue<RevaMessage> toRevaQueue = new LinkedBlockingQueue<RevaMessage>();
    /**
     * A queue of messages received from ReVa.
     */
    private BlockingQueue<RevaMessage> toToolQueue = new LinkedBlockingQueue<RevaMessage>();



    /**
     * Send a message to ReVa
     * @param message the message to send
     */
    public void sendMessage(RevaMessage message) {
        Msg.info(this, message.toJson());
        this.toRevaQueue.add(message);
    }

    /**
     * Create a new RevaService.
     * @param program the program to provide services for
     */
    public RevaService(Program program) {
        super("RevaService");
        this.currentProgram = program;
        // Note, Program can be null here.
        //this.revaProjectPath = REVA_CACHE_DIR.resolve("projects").resolve(program.getName());

    }

    /**
     * Run the main communications thread. This will make HTTP requests to the ReVa tool.
     */
    public void run(TaskMonitor monitor) {
        // Monitor the to-tool directory for messages from ReVa.

       // TODO: Loop and run the communications function
       Msg.trace(this, "ReVa communications thread starting");
    }


    /**
     * Get the bytes at the given address.
     * @param addr the address to get bytes from
     * @param numBytes the number of bytes to get
     * @return the bytes at the given address
     * @throws NotImplementedException if the method is not implemented
     */
    public byte[] getBytes(Address addr, int numBytes) throws MemoryAccessException {
        byte[] bytes = new byte[numBytes];
        currentProgram.getMemory().getBytes(addr, bytes);
        return bytes;
    }
}
