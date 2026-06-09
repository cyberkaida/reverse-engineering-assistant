package reva.services;

import java.util.Map;
import ghidra.util.task.TaskMonitor;

/**
 * A unit of diff work executed on the background worker. Implementations run the domain logic
 * (VT correlation or markup transfer), passing {@code monitor} down to Ghidra so progress is
 * logged and cancellation propagates, and return the tool's JSON result map.
 */
@FunctionalInterface
public interface DiffWork {
    Map<String, Object> run(TaskMonitor monitor) throws Exception;
}
