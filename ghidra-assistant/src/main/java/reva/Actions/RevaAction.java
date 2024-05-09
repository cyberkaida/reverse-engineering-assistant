package reva.Actions;

import ghidra.program.model.address.Address;

/**
 * A RevaAction is a thing the LLM has requested be
 * completed. These are sent to the monitoring UI
 * for the user to accept or reject.
 */
public class RevaAction {
    public enum Status {
        PENDING,
        ACCEPTED,
        REJECTED
    }

    public static class Builder {
        Address location;
        String name;
        String description;
        Runnable onAccepted;
        Runnable onRejected;

        public Builder() {}

        public Builder setLocation(Address location) {
            this.location = location;
            return this;
        }

        public Builder setName(String name) {
            this.name = name;
            return this;
        }

        public Builder setDescription(String description) {
            this.description = description;
            return this;
        }

        public Builder setOnAccepted(Runnable onAccepted) {
            this.onAccepted = onAccepted;
            return this;
        }

        public Builder setOnRejected(Runnable onRejected) {
            this.onRejected = onRejected;
            return this;
        }

        public RevaAction build() {
            return new RevaAction(location, name, description, onAccepted, onRejected);
        }
    }

    public RevaAction(
            Address location,
            String name,
            String description,
            Runnable onAccepted,
            Runnable onRejected
    ) {
        this.location = location;
        this.name = name;
        this.description = description;
        this.status = Status.PENDING;
        this.onAccepted = onAccepted;
        this.onRejected = onRejected;
    }

    public final Address location;
    public final String name;
    public final String description;
    public final Runnable onAccepted;
    public final Runnable onRejected;
    public Status status = Status.PENDING;

    public void accept() {
        if (status == Status.PENDING) {
            onAccepted.run();
            status = Status.ACCEPTED;
        }
    }

    public void reject() {
        if (status == Status.PENDING) {
            onRejected.run();
            status = Status.REJECTED;
        }
    }
}
