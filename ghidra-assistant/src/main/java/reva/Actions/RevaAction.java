package reva.Actions;

import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import reva.RevaPlugin;

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
        RevaPlugin plugin;
        Address location;
        String name;
        String description;
        Runnable onAccepted = null;
        Runnable onRejected = null;

        public Builder() {}

        public Builder setPlugin(RevaPlugin plugin) {
            this.plugin = plugin;
            return this;
        }

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
            return new RevaAction(plugin, location, name, description, onAccepted, onRejected);
        }
    }

    public RevaAction(
            RevaPlugin plugin,
            Address location,
            String name,
            String description,
            Runnable onAccepted,
            Runnable onRejected
    ) {

        assert plugin != null;
        assert name != null;
        if (description == null) {
            description = name;
        }
        if (location == null) {
            Msg.debug(this, "Location is null, setting to current program's min address");
            location = plugin.getCurrentProgram().getMinAddress();
        }
        this.plugin = plugin;
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
    private final Runnable onAccepted;
    private final Runnable onRejected;
    public Status status = Status.PENDING;
    private RevaPlugin plugin = null;

    public void accept() {
        Msg.debug(this, String.format("Accepting action %s", name));
        if (status == Status.PENDING) {
            if (plugin != null && plugin.revaFollowEnabled()) {
                Msg.info(this, "Going to location: " + location.toString());
                plugin.goTo(location);
            }

            if (onAccepted != null) {
                onAccepted.run();
            }
            status = Status.ACCEPTED;
        }
    }

    public void reject() {
        Msg.info(this, String.format("Rejecting action %s", name));
        if (status == Status.PENDING) {
            if (onRejected != null) {
                onRejected.run();
            }
            status = Status.REJECTED;
        }
    }
}
