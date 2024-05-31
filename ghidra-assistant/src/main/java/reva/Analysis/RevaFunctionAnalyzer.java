package reva.Analysis;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.Analyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import reva.RevaChatService;

public class RevaFunctionAnalyzer implements Analyzer {

    RevaChatService getRevaChat(Program program) {
        AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
		PluginTool tool = analysisManager.getAnalysisTool();
        return tool.getService(RevaChatService.class);
    }

    @Override
    public boolean added(Program program, AddressSetView changed, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        RevaChatService chat = getRevaChat(program);
        monitor.setMaximum(program.getFunctionManager().getFunctionCount());
        program.getFunctionManager().getFunctions(true).forEachRemaining((function) -> {
            if (monitor.isCancelled()) {
                monitor.incrementProgress();
                return;
            }

            if (!function.isThunk() && this.shouldCleanFunctions) {
                monitor.setMessage(String.format("Cleaning up %s", function.getName()));
                String revaResponse = chat.revaChat(
                    String.format("Examine the decompilation of the function '%s' and improve the decompilation with your tools.", function.getName(true))
                );
                log.appendMsg(this.getName(), revaResponse);
            }

            if (!function.isThunk() && this.shouldRenameUnnamedThings && function.getName().startsWith("FUN_")) {
                // This might not be named yet!
                monitor.setMessage(String.format("Renaming %s", function.getName()));
                String revaResponse = chat.revaChat(
                    String.format("Examine the function '%s' in its context. Improve the Ghidra decompilation with your tools, then rename the function.", function.getName(true))
                );
                log.appendMsg(this.getName(), revaResponse);
            }

            if (!function.isThunk() && this.shouldCommentFunctions) {
                monitor.setMessage(String.format("Commenting %s", function.getName()));
                String revaResponse = chat.revaChat(
                    String.format("Examine the decompilation of the function '%s' and comment important parts. Don't be too verbose.", function.getName(true))
                );
                log.appendMsg(this.getName(), revaResponse);
            }

            monitor.incrementProgress();
        });

        return true;
    }

    @Override
    public void analysisEnded(Program program) {
    }

    @Override
    public boolean canAnalyze(Program program) {
        // ReVa can analyse anything because we are so smart!
        return true;
    }

    @Override
    public AnalyzerType getAnalysisType() {
        return AnalyzerType.FUNCTION_ANALYZER;
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return false;
    }

    @Override
    public String getDescription() {
        return "Examine functions with ReVa.";
    }

    @Override
    public String getName() {
        return "ReVa Function triage";
    }

    @Override
    public AnalysisPriority getPriority() {
        return AnalysisPriority.LOW_PRIORITY;
    }

    @Override
    public boolean isPrototype() {
        return true;
    }

    private boolean shouldRenameUnnamedThings = true;
    private boolean shouldCleanFunctions = false;
    private boolean shouldCommentFunctions = false;

    @Override
    public void optionsChanged(Options options, Program program) {
        this.shouldRenameUnnamedThings = options.getBoolean("Rename unnamed things", true);
        this.shouldCleanFunctions = options.getBoolean("Clean functions", false);
        this.shouldCommentFunctions = options.getBoolean("Comment functions", false);
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption("Clean functions", OptionType.BOOLEAN_TYPE, false, null, "Ask ReVa to clean up every function. Takes a long time");
        options.registerOption("Rename unnamed things", OptionType.BOOLEAN_TYPE, true, null, "Rename things with default names");
        options.registerOption("Comment functions", OptionType.BOOLEAN_TYPE, false, null, "Add comments to every function");
    }


    @Override
    public boolean removed(Program program, AddressSetView addressSet, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        return true;
    }

    @Override
    public boolean supportsOneTimeAnalysis() {
        return true;
    }

}
