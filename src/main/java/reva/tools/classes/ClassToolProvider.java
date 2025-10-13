/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.tools.classes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;

/**
 * Tool provider for reconstructed class operations.
 * Provides tools to access and modify reconstructed class definitions in Ghidra.
 */
public class ClassToolProvider extends AbstractToolProvider {
    
    /**
     * Constructor
     * @param server The MCP server
     */
    public ClassToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() throws McpError {
        registerListClassesTool();
        registerGetClassOrNamespaceInfoTool();
        registerListClassOrNamespaceMethodsTool();
        registerCreateClassTool();
        registerCreateNamespaceTool();
        registerAssociateFunctionWithClassOrNamespaceTool();
        registerAssociateVariableOrVtableWithClassTool();
        registerReconstructClassesFromRttiTool();
    }   

    /**
     * Register a tool to list all class namespaces in a program
     * @throws McpError if there's an error registering the tool
     */
    private void registerListClassesTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("maxCount", SchemaUtil.integerPropertyWithDefault("Maximum number of classes to return", 100));
        properties.put("startIndex", SchemaUtil.integerPropertyWithDefault("Starting index for pagination (0-based)", 0));

        List<String> required = List.of("programPath");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-classes")
            .title("List Classes")
            .description("List all classes in a program with their basic information")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, args) -> {
            try {
                Program program = getProgramFromArgs(args);
                int maxCount = getOptionalInt(args, "maxCount", 100);
                int startIndex = getOptionalInt(args, "startIndex", 0);

                SymbolTable symbolTable = program.getSymbolTable();
                List<Map<String, Object>> classes = new ArrayList<>();
                int currentIndex = 0;

                // Use the proper getClassNamespaces() method to get all class namespaces
                Iterator<GhidraClass> classIterator = symbolTable.getClassNamespaces();
                while (classIterator.hasNext() && classes.size() < maxCount) {
                    GhidraClass ghidraClass = classIterator.next();
                    
                    if (ghidraClass == null) {
                        continue;
                    }

                    if (currentIndex < startIndex) {
                        currentIndex++;
                        continue;
                    }

                    if (classes.size() >= maxCount) {
                        break;
                    }

                    // Get function count for this namespace using SymbolTable (more efficient)
                    int functionCount = 0;
                    SymbolIterator symbols = symbolTable.getSymbols(ghidraClass);
                    while (symbols.hasNext()) {
                        if (symbols.next().getSymbolType() == SymbolType.FUNCTION) {
                            functionCount++;
                        }
                    }

                    Map<String, Object> classInfo = createBasicNamespaceInfo(ghidraClass, functionCount);
                    classes.add(classInfo);
                    currentIndex++;
                }

                // Create metadata
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("totalFound", currentIndex);
                metadata.put("returned", classes.size());
                metadata.put("startIndex", startIndex);
                metadata.put("maxCount", maxCount);
                
                // Add guidance when no classes are found
                if (classes.isEmpty()) {
                    metadata.put("guidance", "No classes found in the program. If this program contains C++ code compiled with RTTI support, " +
                        "you may be able to reconstruct classes from RTTI data using the 'reconstruct-classes-from-rtti' tool.");
                }

                List<Object> resultData = new ArrayList<>();
                resultData.add(metadata);
                resultData.addAll(classes);

                return createMultiJsonResult(resultData);

            } catch (Exception e) {
                Msg.error(this, "Error listing classes", e);
                return createErrorResult("Error listing classes: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to get detailed information about a specific class or namespace
     * @throws McpError if there's an error registering the tool
     */
    private void registerGetClassOrNamespaceInfoTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("className", SchemaUtil.stringProperty("Name of the class or namespace"));

        List<String> required = List.of("programPath", "className");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-class-info")
            .title("Get Class Information")
            .description("Get detailed information about a specific class or namespace including methods, structure, and inheritance")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, args) -> {
            try {
                Program program = getProgramFromArgs(args);
                String className = getString(args, "className");

                Namespace namespace = getNamespaceFromPath(program, className);
                if (namespace == null) {
                    throw new Exception("Class namespace not found: " + className + 
                        ". Use 'list-classes' to see available classes or try reconstructing classes from RTTI data if this is a C++ program.");
                }

                Map<String, Object> classInfo = createDetailedNamespaceInfo(namespace, program);
                classInfo.put("found", true);
                return createJsonResult(classInfo);

            } catch (Exception e) {
                Msg.error(this, "Error getting class info", e);
                return createErrorResult("Error getting class info: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to list methods in a class
     * @throws McpError if there's an error registering the tool
     */
    private void registerListClassOrNamespaceMethodsTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("name", SchemaUtil.stringProperty("Name of the class or namespace (ParentNamespace"+Namespace.DELIMITER+"NamespaceOrClassName)"));

        List<String> required = List.of("programPath", "name");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-class-or-namespace-methods")
            .title("List Class Methods")
            .description("List all methods in a class or namespace with detailed information including signatures and types")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, args) -> {
            try {
                Program program = getProgramFromArgs(args);
                String name = getString(args, "name");

                Namespace namespace = getNamespaceFromPath(program, name);

                if (namespace == null) {
                    throw new Exception("Namespace not found: " + name + 
                        ". Use 'list-classes' to see available classes or try reconstructing classes from RTTI data if this is a C++ program.");
                }

                List<Map<String, Object>> methods = getNamespaceMethods(namespace, program);
                
                Map<String, Object> result = new HashMap<>();
                result.put("name", name);
                result.put("methodCount", methods.size());
                result.put("methods", methods);

                return createJsonResult(result);

            } catch (Exception e) {
                Msg.error(this, "Error listing methods", e);
                return createErrorResult("Error listing methods: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to create a new class namespace
     * @throws McpError if there's an error registering the tool
     */
    private void registerCreateClassTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("className", SchemaUtil.stringProperty("Name of the class to create or modify"));
        properties.put("parentNamespace", SchemaUtil.stringProperty("Parent class or namespace (not superclass, this is the class or namespace containing the class (ParentNamespaceOrClass"+Namespace.DELIMITER+"Class)) (optional, defaults to global namespace)"));

        List<String> required = List.of("programPath", "className");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("create-class")
            .title("Create Class")
            .description("Create a new class to be reconstructed")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, args) -> {
            try {
                Program program = getProgramFromArgs(args);
                String className = getString(args, "className");
                String parentNamespaceName = getOptionalString(args, "parentNamespace", "");

                SymbolTable symbolTable = program.getSymbolTable();
                
                // Find parent namespace
                Namespace parentNamespace = program.getGlobalNamespace();
                if (!parentNamespaceName.isEmpty()) {
                    parentNamespace = symbolTable.getNamespace(parentNamespaceName, program.getGlobalNamespace());
                    if (parentNamespace == null) {
                        throw new Exception("Parent namespace not found: " + parentNamespaceName);
                    }
                }

                // Check if class already exists using the proper getClassNamespaces() method
                Namespace existingClassNamespace = getNamespaceFromPath(program, className);
                
                if (existingClassNamespace != null) {
                    throw new Exception("Class "+className+" already exists.");
                }

                int txId = program.startTransaction("Create Class Namespace");
                try {
                    // Create the class namespace
                    Namespace classNamespace = symbolTable.createClass(parentNamespace, className, ghidra.program.model.symbol.SourceType.USER_DEFINED);

                    program.endTransaction(txId, true);

                    Map<String, Object> result = createBasicNamespaceInfo(classNamespace, 0);
                    result.put("message", "Successfully created class: " + className);
                    return createJsonResult(result);

                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }

            } catch (Exception e) {
                Msg.error(this, "Error creating class", e);
                return createErrorResult("Error creating class: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to create a new namespace
     * @throws McpError if there's an error registering the tool
     */
    private void registerCreateNamespaceTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("namespaceName", SchemaUtil.stringProperty("Name of the class to create or modify"));
        properties.put("parentNamespace", SchemaUtil.stringProperty("Parent namespace (this is the namespace containing the new namespace (ParentNamespace"+Namespace.DELIMITER+"Class)) (optional, defaults to global namespace)"));

        List<String> required = List.of("programPath", "namespaceName");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("create-namespace")
            .title("Create Namespace")
            .description("Create a new namespace to be reconstructed")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, args) -> {
            try {
                Program program = getProgramFromArgs(args);
                String namespaceName = getString(args, "namespaceName");
                String parentNamespaceName = getOptionalString(args, "parentNamespace", "");

                SymbolTable symbolTable = program.getSymbolTable();
                
                // Find parent namespace
                Namespace parentNamespace = program.getGlobalNamespace();
                if (!parentNamespaceName.isEmpty()) {
                    parentNamespace = symbolTable.getNamespace(parentNamespaceName, program.getGlobalNamespace());
                    if (parentNamespace == null) {
                        throw new Exception("Parent namespace not found: " + parentNamespaceName);
                    }
                }

                // Check if class already exists using the proper getClassNamespaces() method
                Namespace existingClassNamespace = getNamespaceFromPath(program, namespaceName);
                
                if (existingClassNamespace != null) {
                    throw new Exception("Namespace "+namespaceName+" already exists.");
                }

                int txId = program.startTransaction("Create Namespace");
                try {
                    // Create the class namespace
                    Namespace namespace = symbolTable.createNameSpace(parentNamespace, namespaceName, ghidra.program.model.symbol.SourceType.USER_DEFINED);

                    program.endTransaction(txId, true);

                    Map<String, Object> result = createBasicNamespaceInfo(namespace, 0);
                    result.put("message", "Successfully created namespace: " + namespaceName);
                    return createJsonResult(result);

                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }

            } catch (Exception e) {
                Msg.error(this, "Error creating namespace", e);
                return createErrorResult("Error creating namespace: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to associate a function with a class
     * @throws McpError if there's an error registering the tool
     */
    private void registerAssociateFunctionWithClassOrNamespaceTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("functionName", SchemaUtil.stringProperty("Name of the function to associate (can be address in hex format like '0x401000')"));
        properties.put("name", SchemaUtil.stringProperty("Name of the class or namespace to associate the function with (ParentNamespaceOrClass"+Namespace.DELIMITER+"Class)"));
        properties.put("functionAddress", SchemaUtil.stringProperty("Address of the function (optional, used if functionName is not found)"));

        List<String> required = List.of("programPath", "functionName", "name");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("associate-function-with-class-or-namespace")
            .title("Associate Function with Class")
            .description("Associate a function with a class or namespace as a member of said class or namespace. This is useful for organizing reconstructed methods under their appropriate classes/namespaces.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, args) -> {
            try {
                Program program = getProgramFromArgs(args);
                String functionName = getString(args, "functionName");
                String name = getString(args, "name");
                String functionAddress = getOptionalString(args, "functionAddress", null);

                // Find the class namespace
                Namespace classNamespace = getNamespaceFromPath(program, name);
                if (classNamespace == null) {
                    return createErrorResult("Namespace not found: " + name + 
                        ". Use 'list-classes' to see available classes or create the class first with 'create-class'.");
                }

                // Find the function
                Function function = findFunction(program, functionName, functionAddress);
                if (function == null) {
                    return createErrorResult("Function not found: " + functionName + 
                        ". Make sure the function exists or provide a valid function address.");
                }

                Symbol functionSymbol = function.getSymbol();
                Namespace parentNamespace = functionSymbol.getParentNamespace();
                // Check if function is already in this class
                if (parentNamespace != null && classNamespace.equals(functionSymbol.getParentNamespace())) {
                    return createErrorResult("Function '" + function.getName() + "' is already associated with class/namespace '" + name + "'");
                }

                int txId = program.startTransaction("Associate Function with Class");
                try {
                    
                    if (functionSymbol != null) {
                        function.setParentNamespace(classNamespace);
                    }

                    program.endTransaction(txId, true);

                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("functionName", function.getName());
                    result.put("functionAddress", AddressUtil.formatAddress(function.getEntryPoint()));
                    result.put("className", name);
                    result.put("newNamespace", classNamespace.getName(true));
                    result.put("message", "Successfully associated function '" + function.getName() + 
                             "' with class/namespace '" + name + "'");
                    
                    return createJsonResult(result);

                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }

            } catch (Exception e) {
                Msg.error(this, "Error associating function with class/namespace", e);
                return createErrorResult("Error associating function with class/namespace: " + e.getMessage());
            }
        });
    }

    /*
     * Register a tool to add functions in a vtable to a class
     * @throws McpError if there's an error registering the tool
     */
    private void registerAssociateVariableOrVtableWithClassTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("className", SchemaUtil.stringProperty("Name of the class to associate the variable or vtable with (ParentClass"+Namespace.DELIMITER+"Class)"));
        properties.put("variableAddress", SchemaUtil.stringProperty("Address or symbol of the variable or vtable to associate"));

        List<String> required = List.of("programPath", "className", "variableAddress");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("associate-variable-or-vtable-with-class")
            .title("Associate Variable with Class")
            .description("Associate a static variable or vtable with a class.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, args) -> {
            try {
                Program program = getProgramFromArgs(args);
                String className = getString(args, "className");
                String addressStr = getString(args, "variableAddress");

                // Find the class namespace
                Namespace classNamespace = getNamespaceFromPath(program, className);
                if (classNamespace == null) {
                    return createErrorResult("Class not found: " + className + 
                        ". Use 'list-classes' to see available classes or create the class first with 'create-class'.");
                }
                if(!(classNamespace instanceof GhidraClass)) {
                    return createErrorResult("Namespace '" + className + "' is not a class. " +
                        "Make sure to create a class using 'create-class' before associating variables or vtables.");
                }

                // Resolve vtable address
                Address address = reva.util.AddressUtil.resolveAddressOrSymbol(program, addressStr);
                if (address == null) {
                    return createErrorResult("Invalid address: " + addressStr);
                }
                // Get the symbol for the vtable at this address
                Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
                if (symbol == null) {
                    return createErrorResult("No symbol found at address: " + addressStr);
                }
                
                int txId = program.startTransaction("Associate variable with Class");
                try {
                    symbol.setNamespace(classNamespace);
                    program.endTransaction(txId, true);

                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("className", className);
                    result.put("message", "Successfully associated '" + symbol.getName() + "' with class/namespace '" + className + "'");
                    
                    return createJsonResult(result);
                }
                catch (Exception e) {
                    program.endTransaction(txId, false);
                    throw e;
                }
            } catch (Exception e) {
                Msg.error(this, "Error associating vtable with class", e);
                return createErrorResult("Error associating vtable with class: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to reconstruct classes from RTTI data
     * @throws McpError if there's an error registering the tool
     */
    private void registerReconstructClassesFromRttiTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("runAnalysis", SchemaUtil.booleanPropertyWithDefault("Run automatic analysis after RTTI reconstruction", false));

        List<String> required = List.of("programPath");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("reconstruct-classes-from-rtti")
            .title("Reconstruct Classes from RTTI")
            .description("Reconstruct classes from Runtime Type Information (RTTI) data using Ghidra's RecoverClassesFromRTTIScript. " +
            "This tool works with Windows PE and GCC programs (32/64-bit) that contain RTTI structures. " +
            "Run this first for best results. (Some binaries may have their RTTI data tampered with, in which case the names recovered will not by accurate, but the types will be correct)")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, args) -> {
            try {
                Program program = getProgramFromArgs(args);
                boolean runAnalysis = getOptionalBoolean(args, "runAnalysis", false);

                Map<String, Object> result = executeRttiReconstruction(program, runAnalysis);
                
                // Check if the result indicates an error
                if (result.containsKey("success") && !((Boolean) result.get("success"))) {
                    return createErrorResult((String) result.get("error"));
                }
                
                return createJsonResult(result);

            } catch (Exception e) {
                Msg.error(this, "Error reconstructing classes from RTTI", e);
                return createErrorResult("Error reconstructing classes from RTTI: " + e.getMessage());
            }
        });
    }

    // Helper methods

    /**
     * Find a class namespace by name
     */
    private Namespace getNamespaceFromPath(Program program, String className) {
        SymbolTable symbolTable = program.getSymbolTable();
        Namespace currentNamespace = program.getGlobalNamespace();
        String[] parts = className.split(Namespace.DELIMITER);
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            Namespace foundNamespace = symbolTable.getNamespace(part, currentNamespace);
            if (foundNamespace == null) {
                // If not found, return null
                return null;
            }
            currentNamespace = foundNamespace;
        }
        return currentNamespace;
    }

    /**
     * Find a function by name or address
     */
    private Function findFunction(Program program, String functionName, String functionAddress) {
        SymbolTable symbolTable = program.getSymbolTable();
        FunctionManager functionManager = program.getFunctionManager();
        Function function = null;

        // First try to resolve as address or symbol
        Address address = reva.util.AddressUtil.resolveAddressOrSymbol(program, functionName);
        if (address != null) {
            // Get the function at this address
            function = functionManager.getFunctionAt(address);
            if (function == null) {
                // Try getting containing function if not exactly at function start
                function = reva.util.AddressUtil.getContainingFunction(program, address);
            }
        }

        // If not found by address, search for symbol by name using SymbolTable
        if (function == null) {
            // Use SymbolTable to find symbols with matching name
            SymbolIterator symbolIter = symbolTable.getSymbols(functionName);
            while (symbolIter.hasNext()) {
                Symbol symbol = symbolIter.next();
                if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                    function = (Function) symbol;
                    if (function != null) {
                        break;
                    }
                }
            }
        }

        return function;
    }

    /**
     * Create basic class information map
     */
    private Map<String, Object> createBasicNamespaceInfo(Namespace classNamespace, int functionCount) {
        Map<String, Object> info = new HashMap<>();
        info.put("name", classNamespace.getName());
        info.put("fullName", classNamespace.getName(true));
        info.put("parentNamespace", classNamespace.getParentNamespace().getName());
        info.put("functionCount", functionCount);
        info.put("isClass", classNamespace instanceof GhidraClass);
        return info;
    }

    /**
     * Create detailed class information map
     */
    private Map<String, Object> createDetailedNamespaceInfo(Namespace classNamespace, Program program) {
        // Add function details
        List<Map<String, Object>> methods = getNamespaceMethods(classNamespace, program);
        Map<String, Object> info = createBasicNamespaceInfo(classNamespace, methods.size());
        info.put("methods", methods);
        return info;
    }

    /**
     * Get methods for a namespace or class
     */
    private List<Map<String, Object>> getNamespaceMethods(Namespace classNamespace, Program program) {
        List<Map<String, Object>> methods = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();
        
        // Get symbols for this namespace and filter for functions (more efficient)
        SymbolIterator symbols = symbolTable.getChildren(classNamespace.getSymbol());
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                Function func = (Function) symbol.getObject();
                if (func != null) {
                    Map<String, Object> methodInfo = createMethodInfo(func);
                    if (methodInfo != null) {
                        methods.add(methodInfo);
                    }
                }
            }
        }
        
        return methods;
    }

    /**
     * Create method information map
     */
    private Map<String, Object> createMethodInfo(Function function) {
        String funcName = function.getName();
        
        Map<String, Object> info = new HashMap<>();
        info.put("name", funcName);
        info.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        info.put("signature", function.getSignature().getPrototypeString());
        info.put("callingConvention", function.getCallingConventionName());
        info.put("parameterCount", function.getParameterCount());
        
        return info;
    }

    /**
     * Execute the RecoverClassesFromRTTIScript to reconstruct classes
     */
    private Map<String, Object> executeRttiReconstruction(Program program, boolean runAnalysis) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Check if the program seems to contain RTTI data first
            if (!checkForRttiIndicators(program)) {
                if (runAnalysis) {
                    // When runAnalysis is true, proceed anyway and let the script determine what to do
                    result.put("rttiDataFound", false);
                    result.put("message", "No obvious RTTI indicators found, but proceeding with analysis as requested");
                    result.put("guidance", "This tool requires a C++ program compiled with RTTI support. " +
                             "Supported formats are Windows PE and GCC programs (32/64-bit). " +
                             "Make sure the RTTI analyzer has been run on this program first.");
                } else {
                    result.put("success", false);
                    result.put("error", "Program does not appear to contain RTTI data");
                    result.put("guidance", "This tool requires a C++ program compiled with RTTI support. " +
                             "Supported formats are Windows PE and GCC programs (32/64-bit). " +
                             "Make sure the RTTI analyzer has been run on this program first.");
                    return result;
                }
            } else {
                result.put("rttiDataFound", true);
            }

            // Count classes before reconstruction
            int classesBefore = countClasses(program);
            
            // Execute the RTTI script
            String scriptName = "RecoverClassesFromRTTIScript.java";
            
            try {
                // Try to find the script - this may fail in test environments
                generic.jar.ResourceFile sourceFile = null;
                try {
                    sourceFile = GhidraScriptUtil.findScriptByName(scriptName);
                } catch (NullPointerException e) {
                    // Script system not initialized (likely test environment)
                    result.put("success", false);
                    result.put("error", "Script system not available: " + e.getMessage());
                    result.put("guidance", "This may occur in test environments where Ghidra script system is not fully initialized. " +
                             "In a full Ghidra environment, ensure the RecoverClassesFromRTTIScript.java is available.");
                    return result;
                }
                
                if (sourceFile == null) {
                    result.put("success", false);
                    result.put("error", "Couldn't find script: " + scriptName);
                    result.put("guidance", "Make sure RecoverClassesFromRTTIScript.java is available in your Ghidra installation. " +
                             "This script is typically located in the Ghidra/Features/DataTypeArchives/ghidra_scripts/ directory.");
                    return result;
                }
                
                // Get script provider
                GhidraScriptProvider provider = GhidraScriptUtil.getProvider(sourceFile);
                if (provider == null) {
                    result.put("success", false);
                    result.put("error", "Couldn't find script provider for: " + scriptName);
                    return result;
                }
                
                // Create output writer
                java.io.PrintWriter writer = new java.io.PrintWriter(System.out);
                
                // Create script instance
                GhidraScript script = provider.getScriptInstance(sourceFile, writer);
                if (script == null) {
                    result.put("success", false);
                    result.put("error", "Failed to create script instance for: " + scriptName);
                    return result;
                }
                
                // Set up script state
                Project project = AppInfo.getActiveProject();
                if (project == null) {
                    result.put("success", false);
                    result.put("error", "No active Ghidra project found");
                    return result;
                }
                
                GhidraState state = new GhidraState(null, project, program, null, null, null);
                TaskMonitor monitor = TaskMonitor.DUMMY;
                
                script.set(state, monitor, writer);
                
                // Run the script with no arguments (script doesn't take arguments)
                String[] scriptArguments = {};
                script.runScript(scriptName, scriptArguments);
                
                // Count classes after reconstruction
                int classesAfter = countClasses(program);
                
                result.put("scriptExecuted", true);
                result.put("scriptName", scriptName);
                result.put("classesBeforeReconstruction", classesBefore);
                result.put("classesAfterReconstruction", classesAfter);
                result.put("classesReconstructed", Math.max(0, classesAfter - classesBefore));
                
                if (classesAfter > classesBefore) {
                    result.put("success", true);
                    result.put("message", String.format("Successfully reconstructed %d classes from RTTI data. " +
                             "Use 'list-classes' to see the reconstructed classes.", 
                             classesAfter - classesBefore));
                } else {
                    result.put("success", false);
                    result.put("error", "RTTI script executed but no new classes were reconstructed");
                    result.put("guidance", "This could mean: " +
                             "1. The program has no RTTI data, " +
                             "2. The RTTI analyzer needs to be run first (Analysis → Auto Analyze → Check 'RTTI Analyzer'), " +
                             "3. The program format is not supported (only Windows PE and GCC programs are supported), or " +
                             "4. Classes were already reconstructed in a previous run.");
                }
                
            } catch (Exception e) {
                result.put("success", false);
                result.put("error", "Error executing " + scriptName + ": " + e.getMessage());
                result.put("exception", e.getClass().getSimpleName());
                result.put("guidance", "The script execution failed. This could be due to: " +
                         "1. The program doesn't contain valid RTTI data, " +
                         "2. The RTTI analyzer hasn't been run yet, or " +
                         "3. The program format is not supported by the script.");
                Msg.error(this, "Error executing RTTI reconstruction script", e);
            }
                     
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", "Error preparing RTTI reconstruction: " + e.getMessage());
            result.put("exception", e.getClass().getSimpleName());
            Msg.error(this, "Error preparing RTTI reconstruction", e);
        }

        return result;
    }

    /**
     * Check for indicators that the program contains RTTI data
     */
    private boolean checkForRttiIndicators(Program program) {
        try {
            ghidra.program.model.symbol.SymbolTable symbolTable = program.getSymbolTable();
            
            // Look for RTTI-related symbols
            ghidra.program.model.symbol.SymbolIterator symbolIter = 
                symbolTable.getAllSymbols(true);
            
            while (symbolIter.hasNext()) {
                ghidra.program.model.symbol.Symbol symbol = symbolIter.next();
                String symbolName = symbol.getName();
                
                // Check for common RTTI symbol patterns
                if (symbolName.contains("class_type_info") ||
                    symbolName.contains("type_info") ||
                    symbolName.contains("vtable") ||
                    symbolName.contains("RTTI") ||
                    symbolName.startsWith("_ZTI") || // GCC typeinfo symbols
                    symbolName.startsWith("_ZTV") || // GCC vtable symbols
                    symbolName.contains("Complete Object Locator")) {
                    return true;
                }
            }
            
            // Check for RTTI-related strings in memory
            ghidra.program.model.mem.Memory memory = program.getMemory();
            byte[] rttiPattern = "class_type_info".getBytes();
            
            for (ghidra.program.model.mem.MemoryBlock block : memory.getBlocks()) {
                if (block.isInitialized()) {
                    try {
                        ghidra.program.model.address.Address found = 
                            memory.findBytes(block.getStart(), block.getEnd(), rttiPattern, null, true, TaskMonitor.DUMMY);
                        if (found != null) {
                            return true;
                        }
                    } catch (Exception e) {
                        // Continue checking other blocks
                    }
                }
            }
            
        } catch (Exception e) {
            // If we can't check for RTTI indicators, assume it might be present
            return true;
        }
        
        return false;
    }

    /**
     * Count the number of class namespaces in a program
     */
    private int countClasses(Program program) {
        int count = 0;
        SymbolTable symbolTable = program.getSymbolTable();
        Iterator<GhidraClass> classIterator = symbolTable.getClassNamespaces();
        while (classIterator.hasNext()) {
            if (classIterator.next() != null) {
                count++;
            }
        }
        return count;
    }
}