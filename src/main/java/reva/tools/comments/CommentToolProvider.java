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
package reva.tools.comments;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.CodeUnitIterator;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;

/**
 * Tool provider for comment-related operations.
 * Provides tools to set, get, remove, and search comments in programs.
 */
public class CommentToolProvider extends AbstractToolProvider {

    private static final Map<String, Integer> COMMENT_TYPES = Map.of(
        "pre", CodeUnit.PRE_COMMENT,
        "eol", CodeUnit.EOL_COMMENT,
        "post", CodeUnit.POST_COMMENT,
        "plate", CodeUnit.PLATE_COMMENT,
        "repeatable", CodeUnit.REPEATABLE_COMMENT
    );

    /**
     * Constructor
     * @param server The MCP server
     */
    public CommentToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() throws McpError {
        registerSetCommentTool();
        registerGetCommentsTool();
        registerRemoveCommentTool();
        registerSearchCommentsTool();
    }

    /**
     * Register a tool to set or update a comment at an address
     * @throws McpError if there's an error registering the tool
     */
    private void registerSetCommentTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("address", SchemaUtil.stringProperty("Address or symbol name where to set the comment"));
        properties.put("commentType", SchemaUtil.stringPropertyWithDefault(
            "Type of comment: 'pre', 'eol', 'post', 'plate', or 'repeatable'", "pre"));
        properties.put("comment", SchemaUtil.stringProperty("The comment text to set"));

        List<String> required = List.of("programPath", "address", "comment");

        McpSchema.Tool tool = new McpSchema.Tool(
            "set-comment",
            "Set or update a comment at a specific address. Use this to keep notes or annotations for yourself and the human.",
            createSchema(properties, required)
        );

        registerTool(tool, (exchange, args) -> {
            String programPath = getString(args, "programPath");
            String addressStr = getString(args, "address");
            String commentTypeStr = getOptionalString(args, "commentType", "eol");
            String comment = getString(args, "comment");

            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find program: " + programPath);
            }

            Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
            if (address == null) {
                return createErrorResult("Invalid address or symbol: " + addressStr);
            }

            Integer commentType = COMMENT_TYPES.get(commentTypeStr.toLowerCase());
            if (commentType == null) {
                return createErrorResult("Invalid comment type: " + commentTypeStr +
                    ". Must be one of: pre, eol, post, plate, repeatable");
            }

            try {
                int transactionId = program.startTransaction("Set Comment");
                try {
                    Listing listing = program.getListing();
                    listing.setComment(address, commentType, comment);

                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("address", address.toString());
                    result.put("commentType", commentTypeStr);
                    result.put("comment", comment);

                    program.endTransaction(transactionId, true);
                    return createJsonResult(result);
                } catch (Exception e) {
                    program.endTransaction(transactionId, false);
                    throw e;
                }
            } catch (Exception e) {
                logError("Error setting comment", e);
                return createErrorResult("Failed to set comment: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to get comments at an address or range
     * @throws McpError if there's an error registering the tool
     */
    private void registerGetCommentsTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("address", SchemaUtil.stringProperty("Address or symbol name to get comments from (optional if using addressRange)"));

        Map<String, Object> addressRangeProps = new HashMap<>();
        addressRangeProps.put("start", SchemaUtil.stringProperty("Start address of the range"));
        addressRangeProps.put("end", SchemaUtil.stringProperty("End address of the range"));
        properties.put("addressRange", Map.of(
            "type", "object",
            "description", "Address range to get comments from (optional if using address)",
            "properties", addressRangeProps
        ));

        properties.put("commentTypes", Map.of(
            "type", "array",
            "description", "Types of comments to retrieve (optional, defaults to all types)",
            "items", Map.of("type", "string")
        ));

        List<String> required = List.of("programPath");

        McpSchema.Tool tool = new McpSchema.Tool(
            "get-comments",
            "Get comments at a specific address or within an address range",
            createSchema(properties, required)
        );

        registerTool(tool, (exchange, args) -> {
            String programPath = getString(args, "programPath");
            String addressStr = getOptionalString(args, "address", null);
            @SuppressWarnings("unchecked")
            Map<String, Object> addressRange = getOptionalMap(args, "addressRange", null);
            @SuppressWarnings("unchecked")
            List<String> commentTypes = (List<String>) args.get("commentTypes");

            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find program: " + programPath);
            }

            AddressSetView addresses;
            if (addressStr != null) {
                Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
                if (address == null) {
                    return createErrorResult("Invalid address or symbol: " + addressStr);
                }
                addresses = new AddressSet(address, address);
            } else if (addressRange != null) {
                String startStr = (String) addressRange.get("start");
                String endStr = (String) addressRange.get("end");

                Address start = AddressUtil.resolveAddressOrSymbol(program, startStr);
                Address end = AddressUtil.resolveAddressOrSymbol(program, endStr);

                if (start == null || end == null) {
                    return createErrorResult("Invalid address range");
                }

                addresses = new AddressSet(start, end);
            } else {
                return createErrorResult("Either 'address' or 'addressRange' must be provided");
            }

            List<Integer> types = new ArrayList<>();
            if (commentTypes != null && !commentTypes.isEmpty()) {
                for (String typeStr : commentTypes) {
                    Integer type = COMMENT_TYPES.get(typeStr.toLowerCase());
                    if (type == null) {
                        return createErrorResult("Invalid comment type: " + typeStr);
                    }
                    types.add(type);
                }
            } else {
                types.addAll(COMMENT_TYPES.values());
            }

            List<Map<String, Object>> comments = new ArrayList<>();
            Listing listing = program.getListing();

            CodeUnitIterator codeUnits = listing.getCodeUnits(addresses, true);
            while (codeUnits.hasNext()) {
                CodeUnit codeUnit = codeUnits.next();
                Address addr = codeUnit.getAddress();

                for (int type : types) {
                    String comment = codeUnit.getComment(type);
                    if (comment != null && !comment.isEmpty()) {
                        Map<String, Object> commentInfo = new HashMap<>();
                        commentInfo.put("address", addr.toString());
                        commentInfo.put("commentType", getCommentTypeName(type));
                        commentInfo.put("comment", comment);
                        comments.add(commentInfo);
                    }
                }
            }

            Map<String, Object> result = new HashMap<>();
            result.put("comments", comments);
            result.put("count", comments.size());

            return createJsonResult(result);
        });
    }

    /**
     * Register a tool to remove a comment at an address
     * @throws McpError if there's an error registering the tool
     */
    private void registerRemoveCommentTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("address", SchemaUtil.stringProperty("Address or symbol name where to remove the comment"));
        properties.put("commentType", SchemaUtil.stringProperty(
            "Type of comment to remove: 'pre', 'eol', 'post', 'plate', or 'repeatable'"));

        List<String> required = List.of("programPath", "address", "commentType");

        McpSchema.Tool tool = new McpSchema.Tool(
            "remove-comment",
            "Remove a specific comment at an address",
            createSchema(properties, required)
        );

        registerTool(tool, (exchange, args) -> {
            String programPath = getString(args, "programPath");
            String addressStr = getString(args, "address");
            String commentTypeStr = getString(args, "commentType");

            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find program: " + programPath);
            }

            Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
            if (address == null) {
                return createErrorResult("Invalid address or symbol: " + addressStr);
            }

            Integer commentType = COMMENT_TYPES.get(commentTypeStr.toLowerCase());
            if (commentType == null) {
                return createErrorResult("Invalid comment type: " + commentTypeStr +
                    ". Must be one of: pre, eol, post, plate, repeatable");
            }

            try {
                int transactionId = program.startTransaction("Remove Comment");
                try {
                    Listing listing = program.getListing();
                    listing.setComment(address, commentType, null);

                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("address", address.toString());
                    result.put("commentType", commentTypeStr);

                    program.endTransaction(transactionId, true);
                    return createJsonResult(result);
                } catch (Exception e) {
                    program.endTransaction(transactionId, false);
                    throw e;
                }
            } catch (Exception e) {
                logError("Error removing comment", e);
                return createErrorResult("Failed to remove comment: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to search for comments containing text
     * @throws McpError if there's an error registering the tool
     */
    private void registerSearchCommentsTool() throws McpError {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("searchText", SchemaUtil.stringProperty("Text to search for in comments"));
        properties.put("caseSensitive", SchemaUtil.booleanPropertyWithDefault("Whether search is case sensitive", false));
        properties.put("commentTypes", Map.of(
            "type", "array",
            "description", "Types of comments to search (optional, defaults to all types)",
            "items", Map.of("type", "string")
        ));
        properties.put("maxResults", SchemaUtil.integerPropertyWithDefault("Maximum number of results to return", 100));

        List<String> required = List.of("programPath", "searchText");

        McpSchema.Tool tool = new McpSchema.Tool(
            "search-comments",
            "Search for comments containing specific text",
            createSchema(properties, required)
        );

        registerTool(tool, (exchange, args) -> {
            String programPath = getString(args, "programPath");
            String searchText = getString(args, "searchText");
            boolean caseSensitive = getOptionalBoolean(args, "caseSensitive", false);
            @SuppressWarnings("unchecked")
            List<String> commentTypes = (List<String>) args.get("commentTypes");
            int maxResults = getOptionalInt(args, "maxResults", 100);

            Program program = RevaProgramManager.getProgramByPath(programPath);
            if (program == null) {
                return createErrorResult("Failed to find program: " + programPath);
            }

            List<Integer> types = new ArrayList<>();
            if (commentTypes != null && !commentTypes.isEmpty()) {
                for (String typeStr : commentTypes) {
                    Integer type = COMMENT_TYPES.get(typeStr.toLowerCase());
                    if (type == null) {
                        return createErrorResult("Invalid comment type: " + typeStr);
                    }
                    types.add(type);
                }
            } else {
                types.addAll(COMMENT_TYPES.values());
            }

            String searchLower = caseSensitive ? searchText : searchText.toLowerCase();
            List<Map<String, Object>> results = new ArrayList<>();
            Listing listing = program.getListing();

            for (int type : types) {
                if (results.size() >= maxResults) break;

                AddressIterator commentAddrs = listing.getCommentAddressIterator(
                    type, program.getMemory(), true);

                while (commentAddrs.hasNext() && results.size() < maxResults) {
                    Address addr = commentAddrs.next();
                    String comment = listing.getComment(type, addr);

                    if (comment != null) {
                        String commentLower = caseSensitive ? comment : comment.toLowerCase();
                        if (commentLower.contains(searchLower)) {
                            Map<String, Object> result = new HashMap<>();
                            result.put("address", addr.toString());
                            result.put("commentType", getCommentTypeName(type));
                            result.put("comment", comment);

                            CodeUnit cu = listing.getCodeUnitAt(addr);
                            if (cu != null) {
                                result.put("codeUnit", cu.toString());
                            }

                            results.add(result);
                        }
                    }
                }
            }

            Map<String, Object> result = new HashMap<>();
            result.put("searchText", searchText);
            result.put("caseSensitive", caseSensitive);
            result.put("results", results);
            result.put("count", results.size());
            result.put("maxResults", maxResults);

            return createJsonResult(result);
        });
    }

    /**
     * Get the string name for a comment type constant
     * @param commentType The comment type constant
     * @return The string name
     */
    private String getCommentTypeName(int commentType) {
        for (Map.Entry<String, Integer> entry : COMMENT_TYPES.entrySet()) {
            if (entry.getValue() == commentType) {
                return entry.getKey();
            }
        }
        return "unknown";
    }
}