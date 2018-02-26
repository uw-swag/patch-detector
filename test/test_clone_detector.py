import unittest
import clone_detector


class TestCloneDetector(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_tokenizer(self):
        # Given
        java_code = 'System.out.println("Hello " + "world");'
        expected = ['System', '.', 'out', '.', 'println', '(', '"Hello "', '+', '"world"', ')', ';']

        # When
        tokens = clone_detector.tokenize(java_code)

        # Then
        self.assertListEqual(tokens, expected)

    def test_tokenizer_annotation(self):
        # Given
        java_code = "    @Override"
        expected = ["@", "Override"]

        # When
        tokens = clone_detector.tokenize(java_code)

        # Then
        self.assertListEqual(tokens, expected)

    # def test_tokenizer_comment_block(self):
    #
    #     # Given
    #     java_code = "    /**      * <p>      * </p>      *       */"
    #     expected = ["/**", "*", "<p>", "*", "</p>", "*", "*/"]
    #
    #     # When
    #     tokens = clone_detector.tokenize(java_code)
    #
    #     # Then
    #     self.assertListEqual(tokens, expected)

    def test_get_n_grams(self):
        # Given
        java_code = ['System.out.println("Hello " + "world");']
        expected = ['System . out .', '. out . println', 'out . println (', '. println ( "Hello "',
                    'println ( "Hello " +', '( "Hello " + "world"', '"Hello " + "world" )',
                    '+ "world" ) ;']

        # When
        n_grams = clone_detector.get_n_grams(java_code)

        # Then
        self.assertListEqual(sorted(n_grams), sorted(expected))

    def test_similarities(self):
        # Given
        old_code = ['System.out.println("Hello " + "world");']
        new_code = ['System.out.println(new Exception("Hello " + "world"));']
        expected = (5. / 8., 5. / 12.)

        # When
        similarity_scores = clone_detector.similarity_scores(old_code, new_code)

        # Then
        self.assertTupleEqual(similarity_scores, expected)

    def test_empty_similarities(self):
        # Given
        expected = (0, 0)

        # When
        similarity_scores = clone_detector.similarity_scores([], [])

        # Then
        self.assertTupleEqual(similarity_scores, expected)

    def test_commonalities(self):
        # Given
        old_code = ['System.out.println("Hello " + "world");']
        new_code = ['System.out.println(new Exception("Hello " + "world"));']
        expected = (5, 8, 12)

        # When
        commonality = clone_detector.commonalities(old_code, new_code)

        # Then
        self.assertTupleEqual(commonality, expected)

    def test_empty_commonalities(self):
        # Given
        expected = (0, 0, 0)

        # When
        commonality = clone_detector.commonalities([], [])

        # Then
        self.assertTupleEqual(commonality, expected)

    def test_commonalities_without_valid_tokens(self):
        # Given
        # Comments don't generate any java tokens
        old_code = ["    /**      * <p>      * </p>      *       */"]
        new_code = ['System.out.println("Hello " + "world");']

        # When
        expected = (0, 0, 8)
        commonality = clone_detector.commonalities(old_code, new_code)

        # Then
        self.assertTupleEqual(commonality, expected)

        # When
        expected = (0, 8, 0)
        commonality = clone_detector.commonalities(new_code, old_code)

        # Then
        self.assertTupleEqual(commonality, expected)

    def test_commonalities_ignoring_javacode(self):

        # Given
        old_code = ['    /**',
                    '     * <p>',
                    '     * Set this to true if you need to post reports to your own server using an',
                    '     * SSL connection with a self-signed certificate.',
                    '     * </p>',
                    '     * ',
                    '     * @return True if SSL certificates validation has to be ignored when',
                    '     *         posting reports.',
                    '     */',
                    '    boolean disableSSLCertValidation() default ACRAConstants.DEFAULT_DISABLE_SSL_CERT_VALIDATION;']
        new_code = ['    /**',
                    '     * <p>',
                    '     * Set this to true if you need to post reports to your own server using an',
                    '     * SSL connection with a self-signed certificate.',
                    '     * </p>',
                    '     * ',
                    '     * @return True if SSL certificates validation has to be ignored when',
                    '     *         posting reports.',
                    '     */',
                    '    boolean disableSSLCertValidation() default ACRAConstants.DEFAULT_ENABLE_SSL_CERT_VALIDATION;']

        # When
        expected = (4, 6, 6)
        commonality = clone_detector.commonalities(old_code, new_code)

        # Then
        self.assertTupleEqual(commonality, expected)


if __name__ == '__main__':
    unittest.main()
