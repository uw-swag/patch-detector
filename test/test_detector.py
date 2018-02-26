import unittest
import detector
from whatthepatch.patch import diffobj


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

    def test_split_changes(self):
        # Given
        changes = [
            (1, None, 'The Way that can be told of is not the eternal Way;'),
            (2, None, 'The name that can be named is not the eternal name.'),
            (3, 1, 'The Nameless is the origin of Heaven and Earth;'),
            (4, None, 'The Named is the mother of all things.'),
            (None, 2, 'The named is the mother of all things.'),
            (None, 3, ''),
            (5, 4, 'Therefore let there always be non-being,'),
            (6, 5, '  so we may see their subtlety,'),
            (7, 6, 'And let there always be being,'),
            (9, 8, 'The two are the same,'),
            (10, 9, 'But after they are produced,'),
            (11, 10, '  they have different names.'),
            (None, 11, 'They both may be called deep and profound.'),
            (None, 12, 'Deeper and more profound,'),
            (None, 13, 'The door of all subtleties!')
        ]
        expected_deletions = ['The Way that can be told of is not the eternal Way;',
                              'The name that can be named is not the eternal name.',
                              'The Named is the mother of all things.']
        expected_additions = ['The named is the mother of all things.',
                              'They both may be called deep and profound.',
                              'Deeper and more profound,',
                              'The door of all subtleties!']

        # When
        diff = diffobj(None, changes, None)
        deletions, additions, one_line_change, prev_line, next_line = detector.split_changes(diff)

        # Then
        self.assertListEqual(deletions, expected_deletions)
        self.assertListEqual(additions, expected_additions)

    def test_split_changes_keep_code(self):
        # Given
        changes = [
            (1, None, 'The Way that can be told of is not the eternal Way;'),
            (2, None, 'The name that can be named is not the eternal name.'),
            (3, 1, 'The Nameless is the origin of Heaven and Earth;'),
            (4, None, 'The Named is the mother of all things.'),
            (None, 2, 'The named is the mother of all things.'),
            (None, 3, ''),
            (5, 4, 'Therefore let there always be non-being,'),
            (6, 5, '  so we may see their subtlety,'),
            (7, 6, 'And let there always be being,'),
            (9, 8, 'The two are the same,'),
            (10, 9, 'But after they are produced,'),
            (11, 10, '  they have different names.'),
            (None, 11, 'They both may be called deep and profound.'),
            (None, 12, 'Deeper and more profound,'),
            (None, 13, 'The door of all subtleties!')
        ]
        expected_old_code = ['The Way that can be told of is not the eternal Way;',
                             'The name that can be named is not the eternal name.',
                             'The Nameless is the origin of Heaven and Earth;',
                             'The Named is the mother of all things.',
                             'Therefore let there always be non-being,',
                             '  so we may see their subtlety,',
                             'And let there always be being,',
                             'The two are the same,',
                             'But after they are produced,',
                             '  they have different names.']
        expected_new_code = ['The Nameless is the origin of Heaven and Earth;',
                             'The named is the mother of all things.',
                             'Therefore let there always be non-being,',
                             '  so we may see their subtlety,',
                             'And let there always be being,',
                             'The two are the same,',
                             'But after they are produced,',
                             '  they have different names.',
                             'They both may be called deep and profound.',
                             'Deeper and more profound,',
                             'The door of all subtleties!']

        # When
        diff = diffobj(None, changes, None)
        old_code, new_code, one_line_change, prev_line, next_line = detector.split_changes(diff, keep_unchanged=True)

        # Then
        self.assertListEqual(old_code, expected_old_code)
        self.assertListEqual(new_code, expected_new_code)


if __name__ == '__main__':
    unittest.main()
