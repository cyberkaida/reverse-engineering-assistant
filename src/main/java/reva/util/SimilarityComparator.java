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
        return findLongestCommonSubstringLength(str2.toLowerCase(), searchString) -
               findLongestCommonSubstringLength(str1.toLowerCase(), searchString);
    }

    private int findLongestCommonSubstringLength(String str1, String str2) {
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
}