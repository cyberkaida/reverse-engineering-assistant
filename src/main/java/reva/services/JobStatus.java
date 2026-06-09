package reva.services;

/** Lifecycle status shared by analysis and diff background jobs. */
public enum JobStatus {
    RUNNING,
    PERSISTING,
    COMPLETED,
    FAILED,
    CANCELLED,
    TIMED_OUT;

    /** @return true if no further transitions are possible. */
    public boolean isTerminal() {
        switch (this) {
            case COMPLETED:
            case FAILED:
            case CANCELLED:
            case TIMED_OUT:
                return true;
            default:
                return false;
        }
    }
}
