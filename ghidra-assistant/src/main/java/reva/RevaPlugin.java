package reva;

import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.task.gui.GProgressBar;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.ProgramLocation;
import ghidra.app.context.ListingActionContext;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.util.Msg;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.stub.StreamObserver;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.ServerSocket;

import docking.action.builder.ActionBuilder;
import reva.Actions.RevaAction;
import reva.Actions.RevaActionTableComponentProvider;
import reva.Handlers.*;
import reva.protocol.RevaChat;
import reva.protocol.RevaChat.RevaChatMessage;
import reva.protocol.RevaChat.RevaChatMessageResponse;
import reva.protocol.RevaChatServiceGrpc.RevaChatServiceStub;
import reva.protocol.RevaVariableOuterClass.RevaVariable;

@PluginInfo(status = PluginStatus.STABLE, // probably a lie
        packageName = "ReVa",
        category = PluginCategoryNames.ANALYSIS,
        shortDescription = "Reverse Engineering Assistant",
        description = "An AI companion for your Ghidra project",
        servicesRequired = {},
        servicesProvided = {}
    )
public class RevaPlugin extends ProgramPlugin {
    TaskMonitor serviceMonitor;
    Server serverHandle;
    RevaActionTableComponentProvider actionTableProvider;
    Options options;

    /**
     * Add an action to track in the UI.
     * Should be called by anything that monitors the
     * database.
     *
     * @param action
     */
    public void addAction(RevaAction action) {
        if (autoAcceptActions()) {
            action.accept();
        }
        // Always add for tracking the action in the UI.
        actionTableProvider.addAction(action);
    }

    public String getExtensionHostname() {
        return "127.0.0.1";
    }

    public String getInferenceHostname() {
        return inferenceHostname;
    }

    public int getExtensionPort() {
        return serverHandle.getPort();
    }

    public int getInferencePort() {
        return inferencePort;
    }

    public boolean autoAcceptActions() {
        return options.getBoolean("Auto-accept ReVa actions", true);
    }

    public enum RevaInferenceType {
        // These values must match to the arguments taken
        // by `reva-server`.
        OpenAI("OpenAI"),
        Ollama("Ollama");

        private String value;

        RevaInferenceType(String string) {
            this.value = string;
        }

        public String getValue() {
            return value;
        }
    }

    public Program getCurrentProgram() {
        return currentProgram;
    }

    @Override
    protected void programActivated(Program program) {
        Msg.info(this, "Starting ReVa service for " + program.getName());
    }

    @Override
    protected void programDeactivated(Program program) {
        // Stop the service
        Msg.info(this, "Stopping ReVa service for " + program.getName());
        serviceMonitor.cancel();
    }

    public String inferenceHostname;
    public int inferencePort;
    public ManagedChannel inferenceChannel = null;

    public void registerInference(String hostname, int port) {
        ManagedChannelBuilder<?> channel = ManagedChannelBuilder.forAddress(hostname, port);
        channel.usePlaintext();
        channel.enableRetry();
        Msg.info(this, String.format("Connected channel to %s:%s", hostname, port));
        inferenceHostname = hostname;
        inferencePort = port;

        inferenceChannel = channel.build();
    }

    public int findAvailablePort() {
        int port = -1;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
            socket.close();
        } catch (IOException e) {
            Msg.error(this, "Error finding an open port: " + e.getMessage());
        }
        return port;
    }

    private void startInferenceServer() {

        RevaInferenceType inferenceType = options.getEnum("Inference type", RevaInferenceType.OpenAI);
        String inferenceTypeString = inferenceType.getValue().toLowerCase();

        TaskBuilder task = new TaskBuilder("ReVa Server", (monitor) -> {
            try {
                Msg.info(this, "Started Extension RPC server...");
                serverHandle.awaitTermination();
                Msg.error(this, "ReVa server exited!");
            } catch (Exception e) {
                Msg.error(this, "Error starting ReVa server: " + e.getMessage());
            }
        });

        TaskBuilder inferenceTask = new TaskBuilder("ReVa Inference", (monitor) -> {
            ProcessBuilder processBuilder = new ProcessBuilder();
            String portString = String.format("%d", serverHandle.getPort());
            String[] command = {
                    "reva-server",
                    "--connect-host", getExtensionHostname(),
                    "--connect-port", portString,
                    "--provider", inferenceTypeString,
                    // Here we pass all our available options, the server will pick the ones it
                    // needs
                    // and ignore the rest.
                    "--openai-model", options.getOptions("OpenAI").getString("OpenAI Model", "gpt-4o"),
                    "--openai-api-key", options.getOptions("OpenAI").getString("OpenAI API Key", "OPENAI_API_KEY"),
                    "--ollama-server-url",
                    options.getOptions("Ollama").getString("Ollama inference URL", "http://localhost:11434"),
                    "--ollama-model", options.getOptions("Ollama").getString("Ollama Model", "llama3")
            };
            processBuilder.command(command);
            Msg.info(this, "Starting inference server with command: " + String.join(" ", command));
            try {
                final Process inferenceProcess = processBuilder.start();
                try {
                    Msg.info(this, String.format("Inference process pid: %d", inferenceProcess.pid()));
                    // If the monitor is cancelled we are going down and we take the inference
                    // process down too
                    monitor.addCancelledListener(() -> {
                        Msg.info(this, "Cancelling inference process...");
                        inferenceProcess.destroy();
                    });

                    int exitCode = inferenceProcess.waitFor();
                    Msg.info(this, "Inference process exited with code: " + exitCode);

                    byte[] errorBytes = inferenceProcess.getErrorStream().readAllBytes();
                    String errorOutput = new String(errorBytes);
                    if (!errorOutput.isEmpty()) {
                        Msg.info(this, "Inference process error output: " + errorOutput);
                    }

                    byte[] outputBytes = inferenceProcess.getInputStream().readAllBytes();
                    String output = new String(outputBytes);
                    if (!output.isEmpty()) {
                        Msg.info(this, "Inference process output: " + output);
                    }

                    Msg.warn(this, "Inference process exited!");
                } catch (Exception e) {
                    Msg.error(this, "Error starting ReVa inference server: " + e.getMessage(), e);
                    if (inferenceProcess != null) {
                        inferenceProcess.destroy();
                    }
                }
            } catch (IOException e) {
                Msg.error(this, "Error starting ReVa inference server: " + e.getMessage(), e);
            }

        }).setCanCancel(true);

        try {
            serverHandle.start();
        } catch (IOException e) {
            Msg.error(this, "Error starting ReVa server: " + e.getMessage(), e);
        }
        task.launchInBackground(serviceMonitor);
        inferenceTask.launchInBackground(serviceMonitor);
    }

    public RevaPlugin(PluginTool tool) {
        super(tool);
        serviceMonitor = new TaskMonitorAdapter(true);
        Msg.info(this, "ReVa plugin loaded!");

        int port = findAvailablePort();
        ServerBuilder<?> server = ServerBuilder.forPort(port);
        // MARK: Register Services
        server.addService(new RevaHandshake(this));
        server.addService(new RevaGetDecompilation(this));
        server.addService(new RevaSymbol(this));
        server.addService(new RevaComment(this));
        server.addService(new RevaGetCursor(this));
        server.addService(new RevaHeartbeat(this));
        server.addService(new RevaData(this));
        server.addService(new RevaReferences(this));
        server.addService(new RevaBookmarks(this));
        serverHandle = server.build();

        options = tool.getOptions("ReVa");
        Options openAiOptions = options.getOptions("OpenAI");
        Options ollamaOptions = options.getOptions("Ollama");

        options.registerOption("Path to reva-server", OptionType.STRING_TYPE, "reva-server", null,
                "Path to the reva-server binary, or `reva-server` if it is on the system path.");
        options.registerOption("Inference type", OptionType.ENUM_TYPE, RevaInferenceType.OpenAI, null,
                "The type of inference server to connect to.");

        openAiOptions.registerOption("OpenAI Model", OptionType.STRING_TYPE, "gpt-4o", null,
                "The OpenAI model to use for inference.");
        openAiOptions.registerOption("OpenAI API Key", OptionType.STRING_TYPE, "OPENAI_API_KEY", null,
                "The OpenAI API key to use for inference. If the magic value 'OPENAI_API_KEY', then the environment variable OPENAI_API_KEY will be used.");

        ollamaOptions.registerOption("Ollama inference URL", OptionType.STRING_TYPE, "http://localhost:11434", null,
                "The URL of the Ollama inference server.");
        ollamaOptions.registerOption("Ollama Model", OptionType.STRING_TYPE, "llama3", null,
                "The Ollama model to use for inference. This must be pulled already.");

        options.registerOption("Auto-accept ReVa actions", OptionType.BOOLEAN_TYPE, true, null,
                "Automatically accept ReVa actions, don't hold them for user review.");
        options.registerOption("Follow ReVa", OptionType.BOOLEAN_TYPE, false, null,
                "Follow ReVa as she takes actions in the program.");

        // Install all the UI hooks
        installMagicRECommand();
        installRevaActionTable();
        installActionRenameSymbol();
        installActionRenameFunctionVariable();
        installActionRetypeFunctionVariable();

        startInferenceServer();
        saveConnectionInfo();
    }

    @Override
    protected void dispose() {
        serverHandle.shutdown();
        this.serviceMonitor.cancel();
        super.dispose();
    }

    /**
     * Given a function name from ReVa, find the function in the current program.
     *
     * @param functionName
     * @return The function, or null if not found.
     */
    public Function findFunction(String functionName) {
        Function function = null;
        for (Function f : this.currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName(true).equals(functionName)) {
                function = f;
                break;
            }
        }

        if (function == null) {
            // Let's find the function by symbol
            for (Symbol symbol : this.currentProgram.getSymbolTable().getAllSymbols(true)) {
                if (symbol.getName().equals(functionName)) {
                    function = this.currentProgram.getFunctionManager().getFunctionAt(symbol.getAddress());
                    if (function != null) {
                        break;
                    }
                }
            }
        }
        return function;
    }

    public Address addressFromAddressOrSymbol(String addressOrSymbol) {
        Address address = this.currentProgram.getAddressFactory().getAddress(addressOrSymbol);
        if (address == null) {
            // OK, it's not an address, let's try a symbol
            SymbolIterator symbols = this.currentProgram.getSymbolTable().getAllSymbols(true);
            if (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                address = symbol.getAddress();
                if (symbol.getName(true).equals(addressOrSymbol)) {
                    return address;
                }
            }
        }
        return address;
    }

    void installRestartInferenceCommand() {
        new ActionBuilder("ReVa Restart Inference", "ReVa")
                .menuPath("ReVa", "Restart Inference")
                .onAction((event) -> {
                    Msg.info(this, "Restart Inference command clicked!");
                    serviceMonitor.cancel();
                    serviceMonitor = new TaskMonitorAdapter(true);
                    startInferenceServer();
                })
                .enabledWhen((context) -> this.inferenceChannel != null)
                .buildAndInstall(tool);
    }

    void installMagicRECommand() {
        new ActionBuilder("Examine here", "ReVa")
                .menuPath("ReVa", "Analyse current location")
                .onAction((event) -> {
                    // Here we'll grab the current location and ask ReVa to
                    // RE the program from here
                    RevaChatServiceStub chatStub = reva.protocol.RevaChatServiceGrpc.newStub(this.inferenceChannel);
                    RevaChatMessage.Builder builder = RevaChatMessage.newBuilder();

                    // Create a monitor to display progress
                    TaskMonitor monitor = new TaskMonitorAdapter();
                    monitor.setIndeterminate(true);
                    monitor.setMessage("ReVa is examining the program...");
                    monitor.setShowProgressValue(true);

                    builder.setMessage(
                            String.format(
                                    "Examine the program at the address `%s`.",
                                    currentLocation.getAddress().toString()));
                    builder.setProgramName(currentProgram.getName());
                    builder.setProject(tool.getProject().getName());
                    StreamObserver<RevaChatMessageResponse> responseStream = new StreamObserver<RevaChat.RevaChatMessageResponse>() {
                        @Override
                        public void onNext(RevaChatMessageResponse value) {
                            Msg.info(this, "ReVa response: " + value.getMessage());
                            monitor.setMessage(value.getMessage());
                            monitor.incrementProgress();
                        }

                        @Override
                        public void onError(Throwable t) {
                            Msg.error(this, "ReVa error: " + t.getMessage());
                            monitor.cancel();
                        }

                        @Override
                        public void onCompleted() {
                            Msg.info(this, "ReVa completed.");
                            monitor.setMessage("ReVa completed.");
                        }
                    };

                    chatStub.chat(builder.build(), responseStream);
                })
                .enabledWhen((context) -> this.inferenceChannel != null)
                .buildAndInstall(tool);
    }

    private void installActionRenameSymbol() {
        new ActionBuilder("ReVa Rename", getName())
                .description("Rename the selection")
                .popupMenuPath("ReVa", "Rename")
                .popupMenuGroup("ReVa")
                .onAction(context -> {
                    RevaChatServiceStub chatStub = reva.protocol.RevaChatServiceGrpc.newStub(this.inferenceChannel);
                    RevaChatMessage.Builder builder = RevaChatMessage.newBuilder();

                    ListingActionContext listingContext = (ListingActionContext) context;

                    ProgramLocation location = listingContext.getLocation();
                    Symbol symbol = listingContext.getProgram().getSymbolTable()
                            .getPrimarySymbol(location.getAddress());
                    if (symbol == null) {
                        Msg.error(this, "No symbol found, we can't rename this yet.");
                        return;
                    }

                    builder.setMessage(
                            String.format(
                                    "Please examnine `%s` in context and rename the symbol `%s` to something more meaningful.",
                                    symbol.getName(),symbol.getName()));
                    builder.setProgramName(currentProgram.getName());
                    builder.setProject(tool.getProject().getName());
                    StreamObserver<RevaChatMessageResponse> responseStream = new StreamObserver<RevaChat.RevaChatMessageResponse>() {
                        @Override
                        public void onNext(RevaChatMessageResponse value) {
                            Msg.info(this, "ReVa response: " + value.getMessage());
                        }

                        @Override
                        public void onError(Throwable t) {
                            Msg.error(this, "ReVa error: " + t.getMessage());
                        }

                        @Override
                        public void onCompleted() {
                            Msg.info(this, "ReVa completed.");
                        }
                    };

                    chatStub.chat(builder.build(), responseStream);
                })
                .enabledWhen(context -> {
                    return context instanceof ListingActionContext;
                })
                .buildAndInstall(tool);
    }

    /**
     * Right click menu action to rename the selected variable.
     *
     * @param tool
     */
    private void installActionRenameFunctionVariable() {
        new ActionBuilder("ReVa Rename", getName())
                .description("Rename the selection")
                .popupMenuPath("ReVa", "Rename")
                .popupMenuGroup("ReVa")
                .onAction(context -> {
                    RevaChatServiceStub chatStub = reva.protocol.RevaChatServiceGrpc.newStub(this.inferenceChannel);
                    RevaChatMessage.Builder builder = RevaChatMessage.newBuilder();

                    DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
                    DecompilerPanel panel = decompilerContext.getDecompilerPanel();

                    ProgramLocation location = panel.getCurrentLocation();
                    var token = panel.getTokenAtCursor();

                    Msg.info(this, "Renaming " + token.getText());
                    HighVariable highVariable = token.getHighVariable();
                    if (highVariable == null) {
                        Msg.error(this, "No high variable found, we can't rename this yet.");
                        return;
                    }

                    builder.setMessage(
                            String.format(
                                    "Examine the context and rename the variable `%s` in the function `%s` to something more meaningful.",
                                    highVariable.getName(),
                                    highVariable.getHighFunction().getFunction().getName(true)));

                    builder.setProgramName(currentProgram.getName());
                    builder.setProject(tool.getProject().getName());
                    StreamObserver<RevaChatMessageResponse> responseStream = new StreamObserver<RevaChat.RevaChatMessageResponse>() {
                        @Override
                        public void onNext(RevaChatMessageResponse value) {
                            Msg.info(this, "ReVa response: " + value.getMessage());
                        }

                        @Override
                        public void onError(Throwable t) {
                            Msg.error(this, "ReVa error: " + t.getMessage());
                        }

                        @Override
                        public void onCompleted() {
                            Msg.info(this, "ReVa completed.");
                        }
                    };

                    chatStub.chat(builder.build(), responseStream);
                })
                .enabledWhen(context -> {
                    return context instanceof DecompilerActionContext;
                })
                .buildAndInstall(tool);
    }

    private void installActionRetypeFunctionVariable() {
        tool = this.tool;
        new ActionBuilder("ReVa ReType", getName())
                .description("Retype the selection")
                .popupMenuPath("ReVa", "Retype")
                .popupMenuGroup("ReVa")
                .onAction(context -> {
                    RevaChatServiceStub chatStub = reva.protocol.RevaChatServiceGrpc.newStub(this.inferenceChannel);
                    RevaChatMessage.Builder builder = RevaChatMessage.newBuilder();

                    DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
                    DecompilerPanel panel = decompilerContext.getDecompilerPanel();

                    ProgramLocation location = panel.getCurrentLocation();
                    var token = panel.getTokenAtCursor();

                    Msg.info(this, "Renaming " + token.getText());
                    HighVariable highVariable = token.getHighVariable();
                    if (highVariable == null) {
                        Msg.error(this, "No high variable found, we can't rename this yet.");
                        return;
                    }

                    builder.setMessage(
                            String.format(
                                    "Examine the context and retype the variable `%s` in the function `%s`.",
                                    highVariable.getName(),
                                    highVariable.getHighFunction().getFunction().getName(true)));

                    builder.setProgramName(currentProgram.getName());
                    builder.setProject(tool.getProject().getName());
                    StreamObserver<RevaChatMessageResponse> responseStream = new StreamObserver<RevaChat.RevaChatMessageResponse>() {
                        @Override
                        public void onNext(RevaChatMessageResponse value) {
                            Msg.info(this, "ReVa response: " + value.getMessage());
                        }

                        @Override
                        public void onError(Throwable t) {
                            Msg.error(this, "ReVa error: " + t.getMessage());
                        }

                        @Override
                        public void onCompleted() {
                            Msg.info(this, "ReVa completed.");
                        }
                    };

                    chatStub.chat(builder.build(), responseStream);
                })
                .enabledWhen(context -> {
                    return context instanceof DecompilerActionContext;
                })
                .buildAndInstall(tool);
    }

    void saveConnectionInfo() {
        // Write our server hostname and port to a well known file
        // in the temp directory to help `reva-chat` find us
        // when it starts up.
        String homeDirectory = System.getProperty("user.home");
        File reva_temp_dir = new File(homeDirectory, ".reva");
        reva_temp_dir.mkdirs();
        File connectionFile = new File(reva_temp_dir,
                String.format("reva-connection-%d.connection", getExtensionPort()));
        // Now write "localhost:port" to the file
        try (FileWriter writer = new FileWriter(connectionFile)) {
            String connectionInfo = String.format("%s:%d", getExtensionHostname(), getExtensionPort());
            writer.write(connectionInfo);
        } catch (IOException e) {
            Msg.error(this, "Error saving connection info: " + e.getMessage());
        }
    }

    void installRevaActionTable() {
        actionTableProvider = new RevaActionTableComponentProvider(this);
        tool.addComponentProvider(actionTableProvider, false);
    }

    public boolean goTo(Address address) {
        return super.goTo(address);
    }

    /**
     * Return true if the view should follow ReVa as she takes actions.
     *
     * @return true if the view should follow ReVa.
     */
    public boolean revaFollowEnabled() {
        return options.getBoolean("Follow ReVa", false);
    }
}
