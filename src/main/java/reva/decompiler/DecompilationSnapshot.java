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
package reva.decompiler;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Immutable copy of everything the tools need from one decompilation: the C text, the signature and,
 * per output line, the addresses of its tokens. Holds no reference to the decompiler's result objects.
 * The lookups reproduce the behaviour of the per-call ClangLine walks they replace.
 */
public final class DecompilationSnapshot {

    /**
     * One decompiler output line.
     *
     * @param lineNumber ClangLine.getLineNumber()
     * @param tokenAddresses getMinAddress() of each token that has one, in token order
     * @param closestAddress DecompilerUtils.getClosestAddress(program, firstToken), or null
     */
    public record Line(int lineNumber, List<Address> tokenAddresses, Address closestAddress) {
        public Line {
            tokenAddresses = List.copyOf(tokenAddresses);
        }
    }

    private final String code;
    private final String signature;
    private final List<Line> lines;
    private final long sizeInChars;

    public DecompilationSnapshot(String code, String signature, List<Line> lines) {
        this.code = code;
        this.signature = signature;
        this.lines = List.copyOf(lines);
        long addresses = 0;
        for (Line line : this.lines) {
            addresses += line.tokenAddresses().size();
            if (line.closestAddress() != null) {
                addresses++;
            }
        }
        this.sizeInChars = (code == null ? 0 : code.length()) + 32L * addresses;
    }

    /**
     * Copy what the tools need out of a completed decompilation.
     */
    public static DecompilationSnapshot from(Program program, DecompileResults results) {
        DecompiledFunction decompiled = results.getDecompiledFunction();
        String code = decompiled.getC();
        String signature = decompiled.getSignature();

        List<Line> lines = new ArrayList<>();
        ClangTokenGroup markup = results.getCCodeMarkup();
        if (markup != null) {
            for (ClangLine clangLine : DecompilerUtils.toLines(markup)) {
                List<ClangToken> tokens = clangLine.getAllTokens();
                List<Address> tokenAddresses = new ArrayList<>();
                for (ClangToken token : tokens) {
                    Address addr = token.getMinAddress();
                    if (addr != null) {
                        tokenAddresses.add(addr);
                    }
                }
                Address closest = tokens.isEmpty() ? null : DecompilerUtils.getClosestAddress(program, tokens.get(0));
                lines.add(new Line(clangLine.getLineNumber(), tokenAddresses, closest));
            }
        }
        return new DecompilationSnapshot(code, signature, lines);
    }

    /** DecompiledFunction.getC(), unmodified. */
    public String code() {
        return code;
    }

    /** DecompiledFunction.getSignature(). */
    public String signature() {
        return signature;
    }

    /** Unmodifiable, in ClangLine order. */
    public List<Line> lines() {
        return lines;
    }

    /** code.length() + 32 per stored address; used by the cache bound. */
    public long sizeInChars() {
        return sizeInChars;
    }

    /**
     * First line (in output order) holding the address: an exact token match, else the closest-address
     * match. Returns -1 if none.
     */
    public int lineForAddress(Address address) {
        if (address == null) {
            return -1;
        }
        for (Line line : lines) {
            if (line.tokenAddresses().contains(address)
                    || (line.closestAddress() != null && line.closestAddress().equals(address))) {
                return line.lineNumber();
            }
        }
        return -1;
    }

    /** First token address on the line, else its closest address; null if the line is absent or has neither. */
    public Address addressForLine(int displayLine) {
        Line line = find(displayLine);
        if (line == null) {
            return null;
        }
        if (!line.tokenAddresses().isEmpty()) {
            return line.tokenAddresses().get(0);
        }
        return line.closestAddress();
    }

    /** Sorted distinct token addresses of the line, or its closest address alone; empty if none. */
    public List<Address> addressesForLine(int displayLine) {
        Line line = find(displayLine);
        if (line == null) {
            return List.of();
        }
        if (!line.tokenAddresses().isEmpty()) {
            return List.copyOf(new TreeSet<>(line.tokenAddresses()));
        }
        return line.closestAddress() != null ? List.of(line.closestAddress()) : List.of();
    }

    /** Each line holding at least one of the addresses as a token address, once, in output order. */
    public List<Integer> linesForAddresses(Collection<Address> addresses) {
        List<Integer> result = new ArrayList<>();
        if (addresses == null || addresses.isEmpty()) {
            return result;
        }
        Set<Address> wanted = new HashSet<>(addresses);
        for (Line line : lines) {
            for (Address addr : line.tokenAddresses()) {
                if (wanted.contains(addr)) {
                    result.add(line.lineNumber());
                    break;
                }
            }
        }
        return result;
    }

    /**
     * The C text lines from contextLines before to contextLines after displayLine (1-based), clamped to
     * the text and joined by "\n". Null if displayLine < 1 or contextLines < 0; an empty window (line far past the end) gives an empty string, as the replaced method did.
     */
    public String context(int displayLine, int contextLines) {
        if (code == null || displayLine <= 0 || contextLines < 0) {
            return null;
        }
        String[] textLines = code.split("\n");
        int start = Math.max(0, displayLine - 1 - contextLines);
        int end = Math.min(textLines.length - 1, displayLine - 1 + contextLines);
        StringBuilder sb = new StringBuilder();
        for (int i = start; i <= end; i++) {
            if (i > start) {
                sb.append("\n");
            }
            sb.append(textLines[i]);
        }
        return sb.toString();
    }

    private Line find(int displayLine) {
        for (Line line : lines) {
            if (line.lineNumber() == displayLine) {
                return line;
            }
        }
        return null;
    }
}
