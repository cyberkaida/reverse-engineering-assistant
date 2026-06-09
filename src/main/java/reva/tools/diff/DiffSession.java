package reva.tools.diff;

import java.util.List;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.program.model.listing.Program;

/** Holder for a cached diff between a source and destination program. */
public final class DiffSession {
    public final Program sourceProgram;
    public final Program destinationProgram;
    public final String sourcePath;
    public final String destinationPath;
    public final VTSession vtSession;
    public final List<String> correlatorsRun;

    public DiffSession(Program source, Program dest, String sourcePath, String destPath,
            VTSession vtSession, List<String> correlatorsRun) {
        this.sourceProgram = source;
        this.destinationProgram = dest;
        this.sourcePath = sourcePath;
        this.destinationPath = destPath;
        this.vtSession = vtSession;
        this.correlatorsRun = correlatorsRun;
    }
}
