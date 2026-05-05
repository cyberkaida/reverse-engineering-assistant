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

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.junit.Test;

/**
 * Unit tests for SimilarityComparator.
 */
public class SimilarityComparatorTest {

    // ========== calculateLcsSimilarity ==========

    @Test
    public void testCalculateLcsSimilarity_IdenticalStrings() {
        double score = SimilarityComparator.calculateLcsSimilarity("hello", "hello");
        assertEquals("Identical strings should give score 1.0", 1.0, score, 0.001);
    }

    @Test
    public void testCalculateLcsSimilarity_CompletelyDifferent() {
        double score = SimilarityComparator.calculateLcsSimilarity("abc", "xyz");
        assertEquals("Completely different strings should give score 0.0", 0.0, score, 0.001);
    }

    @Test
    public void testCalculateLcsSimilarity_NullFirstArg() {
        double score = SimilarityComparator.calculateLcsSimilarity(null, "hello");
        assertEquals("Null first arg should return 0.0", 0.0, score, 0.001);
    }

    @Test
    public void testCalculateLcsSimilarity_NullSecondArg() {
        double score = SimilarityComparator.calculateLcsSimilarity("hello", null);
        assertEquals("Null second arg should return 0.0", 0.0, score, 0.001);
    }

    @Test
    public void testCalculateLcsSimilarity_BothNull() {
        double score = SimilarityComparator.calculateLcsSimilarity(null, null);
        assertEquals("Both null should return 0.0", 0.0, score, 0.001);
    }

    @Test
    public void testCalculateLcsSimilarity_EmptyFirst() {
        double score = SimilarityComparator.calculateLcsSimilarity("", "hello");
        assertEquals("Empty first string should return 0.0", 0.0, score, 0.001);
    }

    @Test
    public void testCalculateLcsSimilarity_EmptySecond() {
        double score = SimilarityComparator.calculateLcsSimilarity("hello", "");
        assertEquals("Empty second string should return 0.0", 0.0, score, 0.001);
    }

    @Test
    public void testCalculateLcsSimilarity_BothEmpty() {
        double score = SimilarityComparator.calculateLcsSimilarity("", "");
        assertEquals("Both empty should return 0.0", 0.0, score, 0.001);
    }

    @Test
    public void testCalculateLcsSimilarity_SubstringContained() {
        // "main" is fully contained in "main_function" → score should be 1.0
        double score = SimilarityComparator.calculateLcsSimilarity("main_function", "main");
        assertEquals("Substring should give score 1.0", 1.0, score, 0.001);
    }

    @Test
    public void testCalculateLcsSimilarity_PartialMatch() {
        // "abc" in "abcxyz": lcs=3, min_len=3 → 1.0
        double score = SimilarityComparator.calculateLcsSimilarity("abcxyz", "abc");
        assertEquals(1.0, score, 0.001);

        // "ab" in "axbx": lcs of "ab" and "axbx" — longest *common substring* not subsequence
        // "ab" has no 2-char run in "axbx", longest common substring is "a" or "b" (length 1)
        // min_len = 2; score = 0.5
        double score2 = SimilarityComparator.calculateLcsSimilarity("axbx", "ab");
        assertEquals(0.5, score2, 0.001);
    }

    @Test
    public void testCalculateLcsSimilarity_ShorterStringDeterminesMax() {
        // score = lcs / min(len1, len2)
        // "fun_main" vs "main": lcs="main"(4), min=4 → 1.0
        double score = SimilarityComparator.calculateLcsSimilarity("fun_main", "main");
        assertEquals(1.0, score, 0.001);
    }

    @Test
    public void testCalculateLcsSimilarity_CaseSensitive() {
        // The method does NOT lowercase; "Hello" vs "hello" differ at first char
        // LCS = "ello" (4), min_len = 5 → 0.8
        double score = SimilarityComparator.calculateLcsSimilarity("Hello", "hello");
        assertEquals(0.8, score, 0.001);
    }

    // ========== compare (Comparator behaviour) ==========

    private SimilarityComparator<String> makeComparator(String searchTerm) {
        return new SimilarityComparator<>(searchTerm,
            new SimilarityComparator.StringExtractor<String>() {
                @Override
                public String extract(String item) {
                    return item;
                }
            });
    }

    @Test
    public void testCompare_MoreSimilarComesFirst() {
        SimilarityComparator<String> cmp = makeComparator("main");

        List<String> names = Arrays.asList("other_function", "FUN_00401000", "main_handler", "calc");
        names.sort(cmp);

        // "main_handler" contains "main" → should be first (highest similarity)
        assertEquals("main_handler should rank first", "main_handler", names.get(0));
    }

    @Test
    public void testCompare_EqualStrings() {
        SimilarityComparator<String> cmp = makeComparator("foo");
        // Both have no match → same score → compare returns 0
        int result = cmp.compare("xyz", "abc");
        assertEquals(0, result);
    }

    @Test
    public void testCompare_FirstMoreSimilar_NegativeResult() {
        SimilarityComparator<String> cmp = makeComparator("main");
        // "main_func" > "other" → compare should return negative (main_func sorts before)
        int result = cmp.compare("main_func", "other_func");
        assertTrue("More similar item should compare as 'less' (earlier in sorted order)", result < 0);
    }

    @Test
    public void testCompare_SecondMoreSimilar_PositiveResult() {
        SimilarityComparator<String> cmp = makeComparator("main");
        // "other_func" < "main_func" → compare should return positive
        int result = cmp.compare("other_func", "main_func");
        assertTrue("Less similar item should compare as 'greater' (later in sorted order)", result > 0);
    }

    @Test
    public void testCompare_NullExtractorValue() {
        SimilarityComparator<String> cmp = new SimilarityComparator<>("search",
            new SimilarityComparator.StringExtractor<String>() {
                @Override
                public String extract(String item) {
                    return null; // null value
                }
            });
        // Should not throw - null is treated as empty string
        int result = cmp.compare("a", "b");
        assertEquals(0, result); // Both null → both score 0 → equal
    }

    @Test
    public void testCompare_SortingIsStable() {
        SimilarityComparator<String> cmp = makeComparator("open");
        List<String> functions = Arrays.asList(
            "FUN_001",
            "open_file",
            "close_file",
            "fopen_wrapper",
            "FUN_002"
        );
        functions.sort(cmp);

        // "open_file" and "fopen_wrapper" both contain "open" and should appear early
        int openFileIdx     = functions.indexOf("open_file");
        int fopenIdx        = functions.indexOf("fopen_wrapper");
        int fun001Idx       = functions.indexOf("FUN_001");
        int fun002Idx       = functions.indexOf("FUN_002");

        // Both open-related functions should rank before non-matching ones
        assertTrue(openFileIdx < fun001Idx);
        assertTrue(openFileIdx < fun002Idx);
        assertTrue(fopenIdx    < fun001Idx);
        assertTrue(fopenIdx    < fun002Idx);
    }

    @Test
    public void testCompare_EmptySearchString() {
        SimilarityComparator<String> cmp = makeComparator("");
        // All items have 0 similarity to empty search (calculateLcsSimilarity returns 0.0 for empty search)
        List<String> names = Arrays.asList("alpha", "beta", "gamma");
        // sort should not throw
        names.sort(cmp);
        assertEquals(3, names.size());
    }

    @Test
    public void testCompare_SearchCaseInsensitive() {
        // Constructor lowercases the search string, extractor values are also lowercased
        SimilarityComparator<String> cmp = makeComparator("MAIN");
        List<String> names = Arrays.asList("other", "main_handler", "unrelated");
        names.sort(cmp);

        // "main_handler" should still rank first because both are lowercased
        assertEquals("main_handler", names.get(0));
    }

    // ========== edge cases for lcs algorithm ==========

    @Test
    public void testCalculateLcsSimilarity_SingleChar_Match() {
        double score = SimilarityComparator.calculateLcsSimilarity("a", "a");
        assertEquals(1.0, score, 0.001);
    }

    @Test
    public void testCalculateLcsSimilarity_SingleChar_NoMatch() {
        double score = SimilarityComparator.calculateLcsSimilarity("a", "b");
        assertEquals(0.0, score, 0.001);
    }

    @Test
    public void testCalculateLcsSimilarity_LongStrings() {
        // Performance sanity check - should complete quickly
        String s1 = "abcdefghijklmnopqrstuvwxyz".repeat(10);
        String s2 = "abcdefghijklmnopqrstuvwxyz".repeat(10);
        double score = SimilarityComparator.calculateLcsSimilarity(s1, s2);
        assertEquals(1.0, score, 0.001);
    }

    @Test
    public void testCalculateLcsSimilarity_RepeatChars() {
        // "aaa" vs "aaaaaa": longest common substring = "aaa" (3), min_len=3, score=1.0
        double score = SimilarityComparator.calculateLcsSimilarity("aaaaaa", "aaa");
        assertEquals(1.0, score, 0.001);
    }

    @Test
    public void testCalculateLcsSimilarity_ScoreBounds() {
        // Score must always be in [0.0, 1.0]
        String[] samples = {"", "a", "abc", "hello world", "FUN_00401000", null};
        for (String s1 : samples) {
            for (String s2 : samples) {
                double score = SimilarityComparator.calculateLcsSimilarity(s1, s2);
                assertTrue("Score must be >= 0", score >= 0.0);
                assertTrue("Score must be <= 1", score <= 1.0 + 0.001);
            }
        }
    }
}
