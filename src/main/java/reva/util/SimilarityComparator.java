package reva.util;


public class SimilarityComparator<T> implements java.util.Comparator<T> {
    
    public static abstract class StringExtractor<T> {
        public abstract String extract(T item);
    }

    private final String searchString;
    private final StringExtractor<T> extractor;

    public SimilarityComparator(String searchString, StringExtractor<T> extractor) {
        this.searchString = searchString.toLowerCase();
        this.extractor = extractor;
    }

    @Override
    public int compare(T o1, T o2) {
        String str1 = extractor.extract(o1);
        String str2 = extractor.extract(o2);
        // Handle null values - treat as empty strings for comparison
        str1 = str1 != null ? str1.toLowerCase() : "";
        str2 = str2 != null ? str2.toLowerCase() : "";
        return findLongestCommonSubstringLength(str2, searchString) -
               findLongestCommonSubstringLength(str1, searchString);
    }

    private int findLongestCommonSubstringLength(String str1, String str2) {
        return lcsLength(str1, str2);
    }

    /**
     * Calculate the longest common substring length between two strings.
     * @param str1 First string
     * @param str2 Second string
     * @return Length of the longest common substring
     */
    private static int lcsLength(String str1, String str2) {
        int m = str1.length();
        int n = str2.length();
        int[][] dp = new int[m + 1][n + 1];
        int maxLength = 0;

        for (int i = 1; i <= m; i++) {
            for (int j = 1; j <= n; j++) {
                if (str1.charAt(i - 1) == str2.charAt(j - 1)) {
                    dp[i][j] = 1 + dp[i - 1][j - 1];
                    if (dp[i][j] > maxLength) {
                        maxLength = dp[i][j];
                    }
                } else {
                    dp[i][j] = 0; // Reset if characters don't match
                }
            }
        }
        return maxLength;
    }

    /**
     * Calculate the LCS-based similarity score between two strings.
     * Returns a value between 0.0 and 1.0, where 1.0 means the longest common
     * substring equals the length of the shorter string (i.e., the shorter
     * string appears as a contiguous substring in the longer string).
     * @param str1 First string (should be lowercase for case-insensitive comparison)
     * @param str2 Second string (should be lowercase for case-insensitive comparison)
     * @return Similarity score between 0.0 and 1.0
     */
    public static double calculateLcsSimilarity(String str1, String str2) {
        if (str1 == null || str2 == null || str1.isEmpty() || str2.isEmpty()) {
            return 0.0;
        }
        int lcsLen = lcsLength(str1, str2);
        int minLen = Math.min(str1.length(), str2.length());
        return (double) lcsLen / minLen;
    }
}
