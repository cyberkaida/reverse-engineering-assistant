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
package reva.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.listing.GhidraClass;

/**
 * Utility class for parsing simplified C++ class definitions and creating corresponding
 * Ghidra structures and classes. Works within Ghidra's API limitations by providing
 * a custom parser for C++-like syntax.
 */
public class CppClassParserUtil {
    
    /**
     * Represents a parsed C++ class definition
     */
    public static class ClassDefinition {
        public String className;
        public String baseClass;
        public List<MemberVariable> members;
        public List<MethodDefinition> methods;
        public boolean hasVirtualMethods;
        
        public ClassDefinition(String className) {
            this.className = className;
            this.members = new ArrayList<>();
            this.methods = new ArrayList<>();
            this.hasVirtualMethods = false;
        }
    }
    
    /**
     * Represents a member variable in a class
     */
    public static class MemberVariable {
        public String type;
        public String name;
        public String comment;
        public boolean isPointer;
        public int arraySize = -1; // -1 means not an array
        
        public MemberVariable(String type, String name, String comment) {
            this.type = type;
            this.name = name;
            this.comment = comment;
            
            // Check for pointer
            if (type.contains("*")) {
                this.isPointer = true;
                this.type = type.replace("*", "").trim();
            }
            
            // Check for array syntax [n]
            Pattern arrayPattern = Pattern.compile("(.+)\\[(\\d+)\\]");
            Matcher arrayMatcher = arrayPattern.matcher(name);
            if (arrayMatcher.find()) {
                this.name = arrayMatcher.group(1);
                this.arraySize = Integer.parseInt(arrayMatcher.group(2));
            }
        }
    }
    
    /**
     * Represents a method definition in a class
     */
    public static class MethodDefinition {
        public String returnType;
        public String methodName;
        public List<String> parameters;
        public boolean isVirtual;
        public boolean isPure;
        public String comment;
        
        public MethodDefinition(String returnType, String methodName, List<String> parameters) {
            this.returnType = returnType;
            this.methodName = methodName;
            this.parameters = parameters != null ? parameters : new ArrayList<>();
            this.isVirtual = false;
            this.isPure = false;
        }
    }
    
    // Regex patterns for parsing
    private static final Pattern CLASS_HEADER = Pattern.compile(
        "class\\s+(\\w+)(?:\\s*:\\s*(?:public|private|protected)?\\s*(\\w+))?\\s*\\{");
    private static final Pattern MEMBER_VARIABLE = Pattern.compile(
        "\\s*(\\w+(?:\\*?)(?:\\[\\d+\\])?)\\s+(\\w+(?:\\[\\d+\\])?)\\s*;\\s*(?://\\s*(.*))?");
    private static final Pattern METHOD_DECLARATION = Pattern.compile(
        "\\s*(virtual\\s+)?(\\w+(?:\\*?)?)\\s+(\\w+)\\s*\\(([^)]*)\\)\\s*(=\\s*0)?\\s*;\\s*(?://\\s*(.*))?");
    
    /**
     * Parse a simplified C++ class definition string
     * 
     * Supports syntax like:
     * class MyClass : public BaseClass {
     *     int member1;
     *     char* name;
     *     int array[10];
     *     virtual int method(int param);
     *     void regularMethod();
     * };
     * 
     * @param classDefinition The C++ class definition string
     * @return Parsed ClassDefinition object
     * @throws IllegalArgumentException if the syntax is invalid
     */
    public static ClassDefinition parseClassDefinition(String classDefinition) throws IllegalArgumentException {
        if (classDefinition == null || classDefinition.trim().isEmpty()) {
            throw new IllegalArgumentException("Class definition cannot be empty");
        }
        
        String cleanDef = classDefinition.trim();
        
        // Parse class header
        Matcher headerMatcher = CLASS_HEADER.matcher(cleanDef);
        if (!headerMatcher.find()) {
            throw new IllegalArgumentException("Invalid class definition syntax. Expected 'class ClassName { ... }'");
        }
        
        String className = headerMatcher.group(1);
        String baseClass = headerMatcher.group(2); // null if no inheritance
        
        ClassDefinition classDef = new ClassDefinition(className);
        classDef.baseClass = baseClass;
        
        // Extract class body (everything between the first { and last })
        int openBrace = cleanDef.indexOf('{');
        int closeBrace = cleanDef.lastIndexOf('}');
        if (openBrace == -1 || closeBrace == -1 || closeBrace <= openBrace) {
            throw new IllegalArgumentException("Invalid class body. Missing or malformed braces.");
        }
        
        String classBody = cleanDef.substring(openBrace + 1, closeBrace);
        String[] lines = classBody.split("\n");
        
        // Parse each line
        for (String line : lines) {
            line = line.trim();
            
            // Skip empty lines and access specifiers
            if (line.isEmpty() || line.equals("public:") || line.equals("private:") || line.equals("protected:")) {
                continue;
            }
            
            // Try to parse as method
            Matcher methodMatcher = METHOD_DECLARATION.matcher(line);
            if (methodMatcher.find()) {
                boolean isVirtual = methodMatcher.group(1) != null;
                String returnType = methodMatcher.group(2);
                String methodName = methodMatcher.group(3);
                String paramString = methodMatcher.group(4);
                boolean isPure = methodMatcher.group(5) != null;
                String comment = methodMatcher.group(6);
                
                List<String> parameters = new ArrayList<>();
                if (paramString != null && !paramString.trim().isEmpty()) {
                    for (String param : paramString.split(",")) {
                        parameters.add(param.trim());
                    }
                }
                
                MethodDefinition method = new MethodDefinition(returnType, methodName, parameters);
                method.isVirtual = isVirtual;
                method.isPure = isPure;
                method.comment = comment;
                
                classDef.methods.add(method);
                if (isVirtual) {
                    classDef.hasVirtualMethods = true;
                }
                continue;
            }
            
            // Try to parse as member variable
            Matcher memberMatcher = MEMBER_VARIABLE.matcher(line);
            if (memberMatcher.find()) {
                String type = memberMatcher.group(1);
                String name = memberMatcher.group(2);
                String comment = memberMatcher.group(3);
                
                MemberVariable member = new MemberVariable(type, name, comment);
                classDef.members.add(member);
                continue;
            }
            
            // If we get here, the line wasn't recognized
            if (!line.startsWith("//")) { // Ignore comment-only lines
                throw new IllegalArgumentException("Unrecognized syntax in line: " + line);
            }
        }
        
        return classDef;
    }
    
    /**
     * Create a GhidraClass and corresponding StructureDataType from a parsed class definition
     * 
     * @param classDef The parsed class definition
     * @param program The target program
     * @param parentNamespace The parent namespace (can be global namespace)
     * @return Map containing created objects and metadata
     * @throws Exception if creation fails
     */
    public static Map<String, Object> createClassInProgram(ClassDefinition classDef, Program program, 
            Namespace parentNamespace) throws Exception {
        
        SymbolTable symbolTable = program.getSymbolTable();
        DataTypeManager dtm = program.getDataTypeManager();
        
        Map<String, Object> result = new HashMap<>();
        
        // Create the GhidraClass namespace
        GhidraClass ghidraClass = symbolTable.createClass(parentNamespace, classDef.className, SourceType.USER_DEFINED);
        
        // Create the class structure for data layout
        StructureDataType classStruct = new StructureDataType(classDef.className, 0);
        
        // Add vtable pointer if class has virtual methods
        if (classDef.hasVirtualMethods) {
            // Create a generic vtable pointer - specific vtable structure would need addresses
            DataType voidPtr = new PointerDataType(VoidDataType.dataType);
            classStruct.add(voidPtr, "vftablePtr", "Virtual function table pointer");
        }
        
        // Add member variables to structure
        for (MemberVariable member : classDef.members) {
            try {
                DataType memberType = resolveDataType(member, dtm);
                if (memberType != null) {
                    classStruct.add(memberType, member.name, member.comment);
                }
            } catch (Exception e) {
                // Continue with other members if one fails
                result.put("warning", "Could not resolve type for member: " + member.name + " (" + member.type + ")");
            }
        }
        
        // Resolve the structure into the data type manager
        DataType resolvedStruct = dtm.resolve(classStruct, DataTypeConflictHandler.REPLACE_HANDLER);
        
        // Build result information
        result.put("success", true);
        result.put("className", classDef.className);
        result.put("baseClass", classDef.baseClass);
        result.put("memberCount", classDef.members.size());
        result.put("methodCount", classDef.methods.size());
        result.put("hasVirtualMethods", classDef.hasVirtualMethods);
        result.put("namespaceCreated", true);
        result.put("structureCreated", true);
        result.put("structureSize", resolvedStruct.getLength());
        
        // Include details about members and methods for reference
        List<Map<String, Object>> memberInfo = new ArrayList<>();
        for (MemberVariable member : classDef.members) {
            Map<String, Object> memberMap = new HashMap<>();
            memberMap.put("name", member.name);
            memberMap.put("type", member.type);
            memberMap.put("isPointer", member.isPointer);
            if (member.arraySize > 0) {
                memberMap.put("arraySize", member.arraySize);
            }
            if (member.comment != null) {
                memberMap.put("comment", member.comment);
            }
            memberInfo.add(memberMap);
        }
        result.put("members", memberInfo);
        
        List<Map<String, Object>> methodInfo = new ArrayList<>();
        for (MethodDefinition method : classDef.methods) {
            Map<String, Object> methodMap = new HashMap<>();
            methodMap.put("name", method.methodName);
            methodMap.put("returnType", method.returnType);
            methodMap.put("parameters", method.parameters);
            methodMap.put("isVirtual", method.isVirtual);
            methodMap.put("isPure", method.isPure);
            if (method.comment != null) {
                methodMap.put("comment", method.comment);
            }
            methodInfo.add(methodMap);
        }
        result.put("methods", methodInfo);
        
        return result;
    }
    
    /**
     * Resolve a member variable's data type using Ghidra's type system
     */
    private static DataType resolveDataType(MemberVariable member, DataTypeManager dtm) throws Exception {
        DataType baseType = null;
        
        // Try to resolve the base type
        try {
            Map<String, Object> typeInfo = DataTypeParserUtil.parseDataTypeFromString(member.type, "", "");
            if (typeInfo != null && typeInfo.containsKey("dataType")) {
                // This would work if we had a program path, but we're working directly with DTM
                // Fall back to basic type resolution
            }
        } catch (Exception e) {
            // Fall back to basic type resolution
        }
        
        // Basic type mapping
        switch (member.type.toLowerCase()) {
            case "char":
                baseType = CharDataType.dataType;
                break;
            case "int":
                baseType = IntegerDataType.dataType;
                break;
            case "long":
                baseType = LongDataType.dataType;
                break;
            case "float":
                baseType = FloatDataType.dataType;
                break;
            case "double":
                baseType = DoubleDataType.dataType;
                break;
            case "void":
                baseType = VoidDataType.dataType;
                break;
            default:
                // Try to find existing type in DTM
                DataType existingType = dtm.getDataType("/" + member.type);
                if (existingType != null) {
                    baseType = existingType;
                } else {
                    // Default to int for unknown types
                    baseType = IntegerDataType.dataType;
                }
                break;
        }
        
        // Apply pointer if needed
        if (member.isPointer) {
            baseType = new PointerDataType(baseType);
        }
        
        // Apply array if needed
        if (member.arraySize > 0) {
            baseType = new ArrayDataType(baseType, member.arraySize, baseType.getLength());
        }
        
        return baseType;
    }
    
    /**
     * Validate a C++ class definition without creating it
     * 
     * @param classDefinition The C++ class definition string
     * @return Map containing validation results
     */
    public static Map<String, Object> validateClassDefinition(String classDefinition) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            ClassDefinition classDef = parseClassDefinition(classDefinition);
            
            result.put("valid", true);
            result.put("className", classDef.className);
            result.put("baseClass", classDef.baseClass);
            result.put("memberCount", classDef.members.size());
            result.put("methodCount", classDef.methods.size());
            result.put("hasVirtualMethods", classDef.hasVirtualMethods);
            result.put("hasInheritance", classDef.baseClass != null);
            
            // Provide summary
            StringBuilder summary = new StringBuilder();
            summary.append("Class '").append(classDef.className).append("'");
            if (classDef.baseClass != null) {
                summary.append(" inherits from '").append(classDef.baseClass).append("'");
            }
            summary.append(" with ").append(classDef.members.size()).append(" members and ")
                   .append(classDef.methods.size()).append(" methods");
            if (classDef.hasVirtualMethods) {
                summary.append(" (has virtual methods)");
            }
            
            result.put("summary", summary.toString());
            
        } catch (IllegalArgumentException e) {
            result.put("valid", false);
            result.put("error", e.getMessage());
            result.put("guidance", "Check your class definition syntax. Expected format: " +
                "class ClassName { type memberName; returnType methodName(params); };");
        } catch (Exception e) {
            result.put("valid", false);
            result.put("error", "Unexpected error: " + e.getMessage());
        }
        
        return result;
    }
}