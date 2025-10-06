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
package reva.tools.bookmarks;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.SchemaUtil;

/**
 * Tool provider for bookmark-related operations.
 * Provides tools to set, get, remove, and search bookmarks in programs.
 */
public class BookmarkToolProvider extends AbstractToolProvider {

    /**
     * Constructor
     * @param server The MCP server
     */
    public BookmarkToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerSetBookmarkTool();
        registerGetBookmarksTool();
        registerRemoveBookmarkTool();
        registerSearchBookmarksTool();
        registerListBookmarkCategoriesTool();
    }

    /**
     * Register a tool to set or update a bookmark at an address
     */
    private void registerSetBookmarkTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("addressOrSymbol", SchemaUtil.stringProperty("Address or symbol name where to set the bookmark"));
        properties.put("type", SchemaUtil.stringProperty("Bookmark type (e.g. 'Note', 'Warning', 'TODO', 'Bug', 'Analysis')"));
        properties.put("category", SchemaUtil.stringProperty("Bookmark category for organizing bookmarks (optional)"));
        properties.put("comment", SchemaUtil.stringProperty("Bookmark comment text"));

        List<String> required = List.of("programPath", "addressOrSymbol", "type", "comment");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("set-bookmark")
            .title("Set Bookmark")
            .description("Set or update a bookmark at a specific address. Used to keep track of important locations in the program.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            Address address = getAddressFromArgs(request, program, "addressOrSymbol");
            String type = getString(request, "type");
            String category = getOptionalString(request, "category", "");
            String comment = getString(request, "comment");

            try {
                int transactionId = program.startTransaction("Set Bookmark");
                try {
                    BookmarkManager bookmarkMgr = program.getBookmarkManager();

                    // Remove existing bookmark of same type/category if exists
                    Bookmark existing = bookmarkMgr.getBookmark(address, type, category);
                    if (existing != null) {
                        bookmarkMgr.removeBookmark(existing);
                    }

                    // Create new bookmark
                    Bookmark bookmark = bookmarkMgr.setBookmark(address, type, category, comment);

                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("id", bookmark.getId());
                    result.put("address", address.toString());
                    result.put("type", type);
                    result.put("category", category);
                    result.put("comment", comment);

                    program.endTransaction(transactionId, true);
                    return createJsonResult(result);
                } catch (Exception e) {
                    program.endTransaction(transactionId, false);
                    throw e;
                }
            } catch (Exception e) {
                logError("Error setting bookmark", e);
                return createErrorResult("Failed to set bookmark: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to get bookmarks at an address or range
     */
    private void registerGetBookmarksTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("addressOrSymbol", SchemaUtil.stringProperty("Address or symbol name to get bookmarks from (optional if using addressRange)"));

        Map<String, Object> addressRangeProps = new HashMap<>();
        addressRangeProps.put("start", SchemaUtil.stringProperty("Start address of the range"));
        addressRangeProps.put("end", SchemaUtil.stringProperty("End address of the range"));
        properties.put("addressRange", Map.of(
            "type", "object",
            "description", "Address range to get bookmarks from (optional if using address)",
            "properties", addressRangeProps
        ));

        properties.put("type", SchemaUtil.stringProperty("Filter by bookmark type (optional)"));
        properties.put("category", SchemaUtil.stringProperty("Filter by bookmark category (optional)"));

        List<String> required = List.of("programPath");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-bookmarks")
            .title("Get Bookmarks")
            .description("Get bookmarks at a specific address or within an address range")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            String addressStr = getOptionalString(request, "addressOrSymbol", null);
            Map<String, Object> addressRange = getOptionalMap(request.arguments(), "addressRange", null);
            String typeFilter = getOptionalString(request, "type", null);
            String categoryFilter = getOptionalString(request, "category", null);

            BookmarkManager bookmarkMgr = program.getBookmarkManager();
            List<Map<String, Object>> bookmarks = new ArrayList<>();

            if (addressStr != null) {
                // Get bookmarks at specific address
                Address address;
                try {
                    address = getAddressFromArgs(Map.of("addressOrSymbol", addressStr), program, "addressOrSymbol");
                } catch (IllegalArgumentException e) {
                    return createErrorResult(e.getMessage());
                }

                Bookmark[] bookmarksAtAddr = bookmarkMgr.getBookmarks(address);
                for (Bookmark bookmark : bookmarksAtAddr) {
                    if (matchesFilters(bookmark, typeFilter, categoryFilter)) {
                        bookmarks.add(bookmarkToMap(bookmark));
                    }
                }
            } else if (addressRange != null) {
                // Get bookmarks in range
                String startStr = (String) addressRange.get("start");
                String endStr = (String) addressRange.get("end");

                Address start, end;
                try {
                    start = getAddressFromArgs(Map.of("addressOrSymbol", startStr), program, "addressOrSymbol");
                    end = getAddressFromArgs(Map.of("addressOrSymbol", endStr), program, "addressOrSymbol");
                } catch (IllegalArgumentException e) {
                    return createErrorResult("Invalid address range: " + e.getMessage());
                }

                AddressSet addrSet = new AddressSet(start, end);
                Iterator<Bookmark> iter = bookmarkMgr.getBookmarksIterator();
                while (iter.hasNext()) {
                    Bookmark bookmark = iter.next();
                    if (addrSet.contains(bookmark.getAddress()) &&
                        matchesFilters(bookmark, typeFilter, categoryFilter)) {
                        bookmarks.add(bookmarkToMap(bookmark));
                    }
                }
            } else {
                // Get all bookmarks with optional filters
                Iterator<Bookmark> iter = typeFilter != null ?
                    bookmarkMgr.getBookmarksIterator(typeFilter) :
                    bookmarkMgr.getBookmarksIterator();

                while (iter.hasNext()) {
                    Bookmark bookmark = iter.next();
                    if (matchesFilters(bookmark, typeFilter, categoryFilter)) {
                        bookmarks.add(bookmarkToMap(bookmark));
                    }
                }
            }

            Map<String, Object> result = new HashMap<>();
            result.put("bookmarks", bookmarks);
            result.put("count", bookmarks.size());

            return createJsonResult(result);
        });
    }

    /**
     * Register a tool to remove a bookmark
     */
    private void registerRemoveBookmarkTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("addressOrSymbol", SchemaUtil.stringProperty("Address or symbol name of the bookmark"));
        properties.put("type", SchemaUtil.stringProperty("Bookmark type"));
        properties.put("category", SchemaUtil.stringProperty("Bookmark category (optional)"));

        List<String> required = List.of("programPath", "addressOrSymbol", "type");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("remove-bookmark")
            .title("Remove Bookmark")
            .description("Remove a specific bookmark")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            Address address = getAddressFromArgs(request, program, "addressOrSymbol");
            String type = getString(request, "type");
            String category = getOptionalString(request, "category", "");

            try {
                int transactionId = program.startTransaction("Remove Bookmark");
                try {
                    BookmarkManager bookmarkMgr = program.getBookmarkManager();
                    Bookmark bookmark = bookmarkMgr.getBookmark(address, type, category);

                    if (bookmark == null) {
                        return createErrorResult("No bookmark found at address " + address +
                            " with type " + type + " and category " + category);
                    }

                    bookmarkMgr.removeBookmark(bookmark);

                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("address", address.toString());
                    result.put("type", type);
                    result.put("category", category);

                    program.endTransaction(transactionId, true);
                    return createJsonResult(result);
                } catch (Exception e) {
                    program.endTransaction(transactionId, false);
                    throw e;
                }
            } catch (Exception e) {
                logError("Error removing bookmark", e);
                return createErrorResult("Failed to remove bookmark: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to search bookmarks
     */
    private void registerSearchBookmarksTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("searchText", SchemaUtil.stringProperty("Text to search for in bookmark comments (optional)"));
        properties.put("types", Map.of(
            "type", "array",
            "description", "Filter by bookmark types (optional)",
            "items", Map.of("type", "string")
        ));
        properties.put("categories", Map.of(
            "type", "array",
            "description", "Filter by bookmark categories (optional)",
            "items", Map.of("type", "string")
        ));

        Map<String, Object> addressRangeProps = new HashMap<>();
        addressRangeProps.put("start", SchemaUtil.stringProperty("Start address of the range"));
        addressRangeProps.put("end", SchemaUtil.stringProperty("End address of the range"));
        properties.put("addressRange", Map.of(
            "type", "object",
            "description", "Limit search to address range (optional)",
            "properties", addressRangeProps
        ));

        properties.put("maxResults", SchemaUtil.integerPropertyWithDefault("Maximum number of results to return", 100));

        List<String> required = List.of("programPath");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("search-bookmarks")
            .title("Search Bookmarks")
            .description("Search for bookmarks by text, type, category, or address range")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            String searchText = getOptionalString(request, "searchText", null);
            List<String> types = getOptionalStringList(request.arguments(), "types", null);
            List<String> categories = getOptionalStringList(request.arguments(), "categories", null);
            Map<String, Object> addressRange = getOptionalMap(request.arguments(), "addressRange", null);
            int maxResults = getOptionalInt(request, "maxResults", 100);

            AddressSetView searchRange = null;
            if (addressRange != null) {
                String startStr = (String) addressRange.get("start");
                String endStr = (String) addressRange.get("end");

                Address start, end;
                try {
                    start = getAddressFromArgs(Map.of("addressOrSymbol", startStr), program, "addressOrSymbol");
                    end = getAddressFromArgs(Map.of("addressOrSymbol", endStr), program, "addressOrSymbol");
                } catch (IllegalArgumentException e) {
                    return createErrorResult("Invalid address range: " + e.getMessage());
                }

                searchRange = new AddressSet(start, end);
            }

            BookmarkManager bookmarkMgr = program.getBookmarkManager();
            List<Map<String, Object>> results = new ArrayList<>();

            Iterator<Bookmark> iter = bookmarkMgr.getBookmarksIterator();
            while (iter.hasNext() && results.size() < maxResults) {
                Bookmark bookmark = iter.next();

                // Check address range
                if (searchRange != null && !searchRange.contains(bookmark.getAddress())) {
                    continue;
                }

                // Check type filter
                if (types != null && !types.isEmpty() && !types.contains(bookmark.getTypeString())) {
                    continue;
                }

                // Check category filter
                if (categories != null && !categories.isEmpty() && !categories.contains(bookmark.getCategory())) {
                    continue;
                }

                // Check text search
                if (searchText != null && !searchText.isEmpty()) {
                    String comment = bookmark.getComment();
                    if (comment == null || !comment.toLowerCase().contains(searchText.toLowerCase())) {
                        continue;
                    }
                }

                results.add(bookmarkToMap(bookmark));
            }

            Map<String, Object> result = new HashMap<>();
            result.put("results", results);
            result.put("count", results.size());
            result.put("maxResults", maxResults);

            return createJsonResult(result);
        });
    }

    /**
     * Register a tool to list bookmark categories for a type
     */
    private void registerListBookmarkCategoriesTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("type", SchemaUtil.stringProperty("Bookmark type to get categories for"));

        List<String> required = List.of("programPath", "type");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-bookmark-categories")
            .title("List Bookmark Categories")
            .description("List all categories for a given bookmark type")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            String type = getString(request, "type");

            BookmarkManager bookmarkMgr = program.getBookmarkManager();
            Map<String, Integer> categoryCounts = new HashMap<>();

            Iterator<Bookmark> iter = bookmarkMgr.getBookmarksIterator(type);
            while (iter.hasNext()) {
                Bookmark bookmark = iter.next();
                String category = bookmark.getCategory();
                if (category == null || category.isEmpty()) {
                    category = "(no category)";
                }
                categoryCounts.put(category, categoryCounts.getOrDefault(category, 0) + 1);
            }

            List<Map<String, Object>> categories = new ArrayList<>();
            for (Map.Entry<String, Integer> entry : categoryCounts.entrySet()) {
                Map<String, Object> categoryInfo = new HashMap<>();
                categoryInfo.put("name", entry.getKey());
                categoryInfo.put("count", entry.getValue());
                categories.add(categoryInfo);
            }

            Map<String, Object> result = new HashMap<>();
            result.put("type", type);
            result.put("categories", categories);
            result.put("totalCategories", categories.size());

            return createJsonResult(result);
        });
    }

    /**
     * Check if a bookmark matches the given filters
     * @param bookmark The bookmark to check
     * @param typeFilter Type filter (null for any)
     * @param categoryFilter Category filter (null for any)
     * @return true if bookmark matches filters
     */
    private boolean matchesFilters(Bookmark bookmark, String typeFilter, String categoryFilter) {
        if (typeFilter != null && !bookmark.getTypeString().equals(typeFilter)) {
            return false;
        }
        if (categoryFilter != null && !bookmark.getCategory().equals(categoryFilter)) {
            return false;
        }
        return true;
    }

    /**
     * Convert a bookmark to a map representation
     * @param bookmark The bookmark to convert
     * @return Map representation of the bookmark
     */
    private Map<String, Object> bookmarkToMap(Bookmark bookmark) {
        Map<String, Object> map = new HashMap<>();
        map.put("id", bookmark.getId());
        map.put("address", bookmark.getAddress().toString());
        map.put("type", bookmark.getTypeString());
        map.put("category", bookmark.getCategory());
        map.put("comment", bookmark.getComment());
        return map;
    }
}