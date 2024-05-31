package reva.Analysis;

import org.apache.commons.lang3.NotImplementedException;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.Analyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import reva.RevaChatService;

public class RevaDataAnalyzer implements Analyzer {

    RevaChatService getRevaChat(Program program) {
        AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
		PluginTool tool = analysisManager.getAnalysisTool();
        return tool.getService(RevaChatService.class);
    }

    @Override
    public boolean added(Program program, AddressSetView changed, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        RevaChatService chat = getRevaChat(program);
        monitor.setIndeterminate(true);

        program.getListing().getData(true).forEachRemaining((data) -> {
            if (monitor.isCancelled()) {
                monitor.incrementProgress();
                return;
            }

            if (data.getLabel() == null) {
                // Nothing to do...
                monitor.incrementProgress();
                return;
            }

            if (this.shouldCreateTypes && data.getLabel().startsWith("DAT_")) {
                monitor.setMessage(String.format("Creating type for %s", data.getPrimarySymbol().getName()));
                String response = chat.revaChat(
                    String.format("Examine the data at '%s' and update its data type. If you are not sure, leave it.", data.getAddress())
                );
                monitor.incrementProgress();
                log.appendMsg(this.getName(), response);
            }

            if (this.shouldRenameUnnamedThings && data.getLabel().startsWith("DAT_")) {
                monitor.setMessage(String.format("Renaming data %s", data.getPrimarySymbol().getName()));
                String response = chat.revaChat(
                    String.format("Examine the data at '%s' and give it an appropriate Ghidra label based on its content and use. If you are not sure, leave it.", data.getAddress())
                );
                monitor.incrementProgress();
                log.appendMsg(this.getName(), response);
            }
        });

        return true;
    }

    @Override
    public void analysisEnded(Program program) {

    }

    @Override
    public boolean canAnalyze(Program program) {
        return true;
    }

    @Override
    public AnalyzerType getAnalysisType() {
        return AnalyzerType.DATA_ANALYZER;
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return false;
    }

    @Override
    public String getDescription() {
        return "Use ReVa to analyse defined data.";
    }

    @Override
    public String getName() {
        return "ReVa Data Triage";
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
    private boolean shouldCreateTypes = true;
    @Override
    public void optionsChanged(Options options, Program program) {
        this.shouldRenameUnnamedThings = options.getBoolean("Rename unnamed things", true);
        this.shouldCreateTypes = options.getBoolean("Create types", true);
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption("Rename unnamed things", OptionType.BOOLEAN_TYPE, true, null, "Rename things with default names");
        options.registerOption("Create types", OptionType.BOOLEAN_TYPE, true, null, "Create types for untyped data");
    }

    @Override
    public boolean supportsOneTimeAnalysis() {
        return true;
    }

    @Override
    public boolean removed(Program arg0, AddressSetView arg1, TaskMonitor arg2, MessageLog arg3)
            throws CancelledException {
        return true;
    }

}
