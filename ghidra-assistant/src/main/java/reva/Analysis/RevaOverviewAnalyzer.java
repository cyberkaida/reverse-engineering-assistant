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

public class RevaOverviewAnalyzer implements Analyzer {

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

        boolean shouldFinalPass = false;

        if (this.shouldFindMaliciousFunctionality) {
            monitor.setMessage("Looking for malicious functionality");
            String response = chat.revaChat("Examine the program and look for malicious functionality. Use Ghidra bookmarks to bookmark what you find in appropriate categories.");
            log.appendMsg(this.getName(), response);
            shouldFinalPass = true;
        }

        if (this.shouldSolveCTFChallenge) {
            monitor.setMessage("Solving CTF challenge");
            String response = chat.revaChat("Examine the program and solve this as a CTF challenge. Use Ghidra bookmarks to bookmark what you find in appropriate categories.");
            log.appendMsg(this.getName(), response);
            shouldFinalPass = true;
        }

        if (this.shouldSearchForVulnerabilities) {
            monitor.setMessage("Searching for vulnerabilities");
            String response = chat.revaChat("Examine the program and search for vulnerabilities. Use Ghidra bookmarks to bookmark what you find in appropriate categories.");
            log.appendMsg(this.getName(), response);
            shouldFinalPass = true;
        }

        if (this.shouldExamineControlFlow) {
            monitor.setMessage("Examine control flow");
            String response = chat.revaChat("Examine the program in detail, start at the entrypoint.");
            log.appendMsg(this.getName(), response);
            shouldFinalPass = true;
        }

        if (shouldFinalPass) {
            monitor.setMessage("ReVa's final pass");
            String response = chat.revaChat("Examine the program, pay attention to the bookmarks.");
            log.appendMsg(this.getName(), response);
        }

        return true;
    }

    @Override
    public void analysisEnded(Program arg0) {
        // OK!
    }

    @Override
    public boolean canAnalyze(Program program) {
        return true;
    }

    @Override
    public AnalyzerType getAnalysisType() {
        return AnalyzerType.FUNCTION_ANALYZER;
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return true;
    }

    @Override
    public String getDescription() {
        return "ReVa can examine the program and answer common questions about it. Most things are bookmarked.";
    }

    @Override
    public String getName() {
        return "ReVa Overview";
    }

    @Override
    public AnalysisPriority getPriority() {
        return AnalysisPriority.LOW_PRIORITY;
    }

    @Override
    public boolean isPrototype() {
        return false;
    }

    private boolean shouldFindMaliciousFunctionality = false;
    private boolean shouldSolveCTFChallenge = false;
    private boolean shouldSearchForVulnerabilities = false;
    private boolean shouldExamineControlFlow = false;

    @Override
    public void optionsChanged(Options options, Program program) {
        this.shouldFindMaliciousFunctionality = options.getBoolean("Find malicious functionality", false);
        this.shouldSolveCTFChallenge = options.getBoolean("Solve CTF challenge", false);
        this.shouldSearchForVulnerabilities = options.getBoolean("Search for vulnerabilities", false);
        this.shouldExamineControlFlow = options.getBoolean("Examine control flow", false);
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption("Find malicious functionality", OptionType.BOOLEAN_TYPE, false, null, "Ask ReVa to look for malicious functionality");
        options.registerOption("Solve CTF challenge", OptionType.BOOLEAN_TYPE, false, null, "Ask ReVa to solve this as a CTF challenge");
        options.registerOption("Search for vulnerabilities", OptionType.BOOLEAN_TYPE, false, null, "Ask ReVa to search for vulnerabilities.");
        options.registerOption("Examine control flow", OptionType.BOOLEAN_TYPE, false, null, "Ask ReVa to start at main and examine the program");
    }

    @Override
    public boolean removed(Program program, AddressSetView changed, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        return true;
    }

    @Override
    public boolean supportsOneTimeAnalysis() {
        return true;
    }
}
