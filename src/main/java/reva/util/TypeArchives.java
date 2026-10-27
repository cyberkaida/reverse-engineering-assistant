package reva.util;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.Optional;

import generic.jar.ResourceFile;
import ghidra.app.services.DataTypeQueryService;
import ghidra.framework.Application;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Opens the data type archives Ghidra ships (Win32 and C library) read-only so
 * C parsing can resolve names such as HANDLE, DWORD and size_t that the
 * program's own data type manager does not contain. Archives are opened once
 * per JVM and shared; a missing archive is skipped with a log line.
 */
public final class TypeArchives {

    private static final String MODULE = "Base";
    private static final Map<String, Optional<DataTypeManager>> CACHE = new ConcurrentHashMap<>();

    private TypeArchives() {
    }

    /**
     * Archives that fit the program: the Win32 archive (by pointer size) for a
     * Windows compiler spec, then the C library archive.
     */
    public static DataTypeManager[] forProgram(Program program) {
        boolean is64 = program.getDefaultPointerSize() > 4;
        List<DataTypeManager> result = new ArrayList<>();
        String compilerId = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
        if ("windows".equalsIgnoreCase(compilerId)) {
            open(is64 ? "typeinfo/win32/windows_vs12_64.gdt" : "typeinfo/win32/windows_vs12_32.gdt")
                .ifPresent(result::add);
        }
        open(is64 ? "typeinfo/generic/generic_clib_64.gdt" : "typeinfo/generic/generic_clib.gdt")
            .ifPresent(result::add);
        return result.toArray(new DataTypeManager[0]);
    }

    /** Archives used when no program is named: 64-bit Win32 and C library. */
    public static DataTypeManager[] defaults() {
        List<DataTypeManager> result = new ArrayList<>();
        open("typeinfo/win32/windows_vs12_64.gdt").ifPresent(result::add);
        open("typeinfo/generic/generic_clib_64.gdt").ifPresent(result::add);
        return result.toArray(new DataTypeManager[0]);
    }

    /**
     * Datatype lookup for C parsers: the program's own types first, then the
     * archives that fit the program. Lets signature parsing resolve names such as
     * {@code HANDLE}, {@code FILE} and {@code size_t} that the program itself
     * does not contain.
     */
    public static DataTypeQueryService queryService(Program program) {
        return new ArchiveQueryService(program.getDataTypeManager(), forProgram(program));
    }

    /**
     * Sort order for the parser's name lookup: case- and space-insensitive name
     * ordering, with manager and category as tie-breakers. The parser
     * binary-searches this list with a space-insensitive, case-insensitive
     * comparator, so the primary key must match that comparison.
     */
    private static final Comparator<DataType> TYPE_ORDER = (a, b) -> {
        String aName = withoutSpaces(a.getName());
        String bName = withoutSpaces(b.getName());
        int result = aName.compareToIgnoreCase(bName);
        if (result != 0) {
            return result;
        }
        result = aName.compareTo(bName);
        if (result != 0) {
            return -result;
        }
        result = managerName(a).compareToIgnoreCase(managerName(b));
        if (result != 0) {
            return result;
        }
        return a.getCategoryPath().getPath().compareToIgnoreCase(b.getCategoryPath().getPath());
    };

    private static final Comparator<CategoryPath> CATEGORY_ORDER = (a, b) -> {
        int result = a.getName().compareToIgnoreCase(b.getName());
        if (result != 0) {
            return result;
        }
        result = a.getName().compareTo(b.getName());
        if (result != 0) {
            return -result;
        }
        return a.getPath().compareToIgnoreCase(b.getPath());
    };

    private static String withoutSpaces(String name) {
        return name.replace(" ", "");
    }

    private static String managerName(DataType dataType) {
        DataTypeManager manager = dataType.getDataTypeManager();
        return manager != null ? manager.getName() : "";
    }

    private static final class ArchiveQueryService implements DataTypeQueryService {
        private final DataTypeManager programTypes;
        private final DataTypeManager[] archives;
        private List<DataType> sortedTypes;

        ArchiveQueryService(DataTypeManager programTypes, DataTypeManager[] archives) {
            this.programTypes = programTypes;
            this.archives = archives;
        }

        @Override
        public List<DataType> getSortedDataTypeList() {
            if (sortedTypes == null) {
                List<DataType> types = new ArrayList<>();
                programTypes.getAllDataTypes(types);
                for (DataTypeManager archive : archives) {
                    archive.getAllDataTypes(types);
                }
                types.sort(TYPE_ORDER);
                sortedTypes = types;
            }
            return sortedTypes;
        }

        @Override
        public List<CategoryPath> getSortedCategoryPathList() {
            Set<CategoryPath> paths = new HashSet<>();
            collectCategories(programTypes.getRootCategory(), paths);
            for (DataTypeManager archive : archives) {
                collectCategories(archive.getRootCategory(), paths);
            }
            List<CategoryPath> result = new ArrayList<>(paths);
            result.sort(CATEGORY_ORDER);
            return result;
        }

        private static void collectCategories(Category category, Set<CategoryPath> paths) {
            paths.add(category.getCategoryPath());
            for (Category child : category.getCategories()) {
                collectCategories(child, paths);
            }
        }

        @Override
        @Deprecated
        @SuppressWarnings("removal")
        public DataType getDataType(String filterText) {
            return promptForDataType(filterText);
        }

        @Override
        public DataType promptForDataType(String filterText) {
            if (filterText == null || filterText.isBlank()) {
                return null;
            }
            // Prefer a type the program already owns over an archive copy.
            List<DataType> programMatches = new ArrayList<>();
            programTypes.findDataTypes(filterText, programMatches);
            if (!programMatches.isEmpty()) {
                return programMatches.get(0);
            }
            String wanted = withoutSpaces(filterText);
            for (DataType dataType : getSortedDataTypeList()) {
                if (withoutSpaces(dataType.getName()).equalsIgnoreCase(wanted)) {
                    return dataType;
                }
            }
            return null;
        }

        @Override
        public List<DataType> findDataTypes(String name, TaskMonitor monitor) {
            List<DataType> result = new ArrayList<>();
            programTypes.findDataTypes(name, result);
            for (DataTypeManager archive : archives) {
                archive.findDataTypes(name, result);
            }
            return result;
        }

        @Override
        public List<DataType> getDataTypesByPath(DataTypePath path) {
            List<DataType> result = new ArrayList<>();
            DataType programType = programTypes.getDataType(path);
            if (programType != null) {
                result.add(programType);
            }
            for (DataTypeManager archive : archives) {
                DataType dataType = archive.getDataType(path);
                if (dataType != null) {
                    result.add(dataType);
                }
            }
            return result;
        }

        @Override
        public DataType getProgramDataTypeByPath(DataTypePath path) {
            return programTypes.getDataType(path);
        }
    }

    private static Optional<DataTypeManager> open(String relativePath) {
        return CACHE.computeIfAbsent(relativePath, path -> {
            try {
                ResourceFile file = Application.getModuleDataFile(MODULE, path);
                return Optional.of(FileDataTypeManager.openFileArchive(file, false));
            } catch (Exception e) {
                Msg.warn(TypeArchives.class, "Type archive " + path + " unavailable, skipping: " + e);
                return Optional.empty();
            }
        });
    }
}
