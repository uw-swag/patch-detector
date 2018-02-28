import unittest
import os
import active_learning
import numpy


class TestActiveLearning(unittest.TestCase):
    result = {}
    labels = {}

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.results = {
            "Acra-5.0.2": {
                "breakdown": {},
                "overall": {
                    "common_additions": 0,
                    "common_deletions": 0,
                    "patch_additions": 226,
                    "patch_additions_score": 0.0,
                    "patch_deletions": 0,
                    "patch_deletions_score": 1.0,
                    "version_additions": 0,
                    "version_additions_score": 0.0,
                    "version_deletions": 0,
                    "version_deletions_score": 1.0
                }
            },
            "acra-4.3.1": {
                "breakdown": {},
                "overall": {
                    "common_additions": 25,
                    "common_deletions": 0,
                    "patch_additions": 226,
                    "patch_additions_score": 0.11061946902654868,
                    "patch_deletions": 0,
                    "patch_deletions_score": 1.0,
                    "version_additions": 30,
                    "version_additions_score": 0.8333333333333334,
                    "version_deletions": 0,
                    "version_deletions_score": 1.0
                }
            },
            "acra-4.4.0": {
                "breakdown": {},
                "overall": {
                    "common_additions": 226,
                    "common_deletions": 128,
                    "patch_additions": 226,
                    "patch_additions_score": 1.0,
                    "patch_deletions": 155,
                    "patch_deletions_score": 0.8258064516129032,
                    "version_additions": 226,
                    "version_additions_score": 1.0,
                    "version_deletions": 155,
                    "version_deletions_score": 0.8258064516129032
                }
            }
        }
        self.labels = {
            "acra-4.3.1": "vulnerable",
            "acra-4.4.0": "not vulnerable"
        }
        self.test_file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'versions_labels.json')

    def tearDown(self):
        pass

    def test_read_versions_labels(self):
        # Given
        expected = {
            "acra-4.3.1": 1,  # vulnerable
            "acra-4.4.0": 0  # not vulnerable
        }

        # When
        with open(self.test_file_path, 'r') as versions_file:
            versions_labels = active_learning.get_versions_labels(versions_file)

        # Then
        self.assertDictEqual(versions_labels, expected)

    def test_preprocess_results(self):
        # Given
        expected_features_train = numpy.array([[25, 0, 226, 0.11061946902654868, 0, 1.0, 30, 0.8333333333333334, 0, 1.0],
                                               [226, 128, 226, 1.0, 155, 0.8258064516129032, 226, 1.0, 155, 0.8258064516129032]])
        expected_labels_train = ["vulnerable", "not vulnerable"]
        expected_features_test = numpy.array([[0, 0, 226, 0.0, 0, 1.0, 0, 0.0, 0, 1.0]])
        expected_versions_test = ["Acra-5.0.2"]

        # When
        features_train, labels_train, features_test, versions_test = active_learning.preprocess_results(self.results,
                                                                                         self.labels)

        # Then
        self.assertTrue(numpy.array_equal(features_train, expected_features_train))
        self.assertListEqual(labels_train, expected_labels_train)
        self.assertTrue(numpy.array_equal(features_test, expected_features_test))
        self.assertListEqual(versions_test, expected_versions_test)

    def test_determine_vulnerability_status(self):

        # Given
        assessed_version = "Acra-5.0.2"
        expected_probabilities = numpy.array([[0.0, 1.0]])  # 0% not vulnerable, 100% vulnerable

        # When
        with open(self.test_file_path, 'r') as versions_file:
            prediction = active_learning.determine_vulnerability_status(self.results, versions_file)

        # Then
        self.assertTrue(numpy.array_equal(prediction, expected_probabilities))
        self.assertTrue(self.results[assessed_version]["vulnerable"])
