package reva;

import java.lang.reflect.Method;

// TODO: Is it too complex to use an annotation?
// Should we create a GhidraPluginService that things can use to register these instead?
public class RevaTool {
    public @interface register {
        String name();
        String description();
    }

    // TODO: Gather all the classes that are RevaTools, then gather all the methods inside
    // and send these over to the RevaService.
}
