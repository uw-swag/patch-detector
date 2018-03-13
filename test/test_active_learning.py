import unittest
import os
import active_learning
import numpy


class TestActiveLearning(unittest.TestCase):
    result = {}
    oracle = {}

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.features = {
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
        self.oracle = {
            "acra-4.3.1": "vulnerable",
            "acra-4.4.0": "not vulnerable",
            "Acra-5.0.2": "not vulnerable"
        }
        self.test_file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'versions_labels.json')

    def tearDown(self):
        pass

    def test_read_versions_labels(self):
        # Given
        expected = {
            "acra-4.3.1": 1,  # vulnerable
            "acra-4.4.0": 0,  # not vulnerable
            "Acra-5.0.2": 0  # not vulnerable
        }

        # When
        with open(self.test_file_path, 'r') as versions_file:
            versions_labels = active_learning.get_versions_labels(versions_file)

        # Then
        self.assertDictEqual(versions_labels, expected)

    def test_preprocess_results(self):
        # Given
        training_versions = ["acra-4.3.1", "acra-4.4.0"]
        expected_features_train = numpy.array(
            [[25, 0, 226, 0.11061946902654868, 0, 1.0, 30, 0.8333333333333334, 0, 1.0],
             [226, 128, 226, 1.0, 155, 0.8258064516129032, 226, 1.0, 155, 0.8258064516129032]])
        expected_labels_train = ["vulnerable", "not vulnerable"]
        expected_features_test = numpy.array([[0, 0, 226, 0.0, 0, 1.0, 0, 0.0, 0, 1.0]])
        expected_labels_test = ["not vulnerable"]
        expected_versions_test = ["Acra-5.0.2"]

        # When
        features_train, labels_train, features_test, labels_test, versions_test = active_learning.preprocess_features(
            self.features,
            self.oracle,
            training_versions)

        # Then
        self.assertTrue(numpy.array_equal(features_train, expected_features_train))
        self.assertListEqual(labels_train, expected_labels_train)
        self.assertTrue(numpy.array_equal(features_test, expected_features_test))
        self.assertListEqual(labels_test, expected_labels_test)
        self.assertListEqual(versions_test, expected_versions_test)

    def test_determine_vulnerability_status(self):
        # Given
        training_versions = ["acra-4.3.1", "acra-4.4.0"]
        assessed_version = "Acra-5.0.2"
        expected_accuracy = 0.667
        expected_next_train_version = "Acra-5.0.2"

        # When
        with open(self.test_file_path, 'r') as versions_file:
            versions = active_learning.get_versions_labels(versions_file)
        accuracy, next_train_version = active_learning.determine_vulnerability_status(self.features, versions,
                                                                                      training_versions)

        # Then
        self.assertTrue(self.features[assessed_version]["vulnerable"])
        self.assertEqual(self.features[assessed_version]["entropy"], 0.0)
        self.assertAlmostEqual(accuracy, expected_accuracy, delta=0.001)
        self.assertEqual(next_train_version, expected_next_train_version)

    def test_entropy_calculation(self):
        # Given
        # A list of predictions from 5 classifiers
        predictions = numpy.array([[0, 0, 0, 0, 0, 1],
                                   [0, 0, 0, 0, 1, 1],
                                   [0, 0, 0, 1, 1, 1],
                                   [0, 0, 1, 1, 1, 1],
                                   [0, 1, 1, 1, 1, 1]])
        expected_votes = numpy.array([0, 0, 0, 1, 1, 1])
        expected_entropies = numpy.array([0, 0.721, 0.971, 0.971, 0.721, 0])

        # When
        calculated_votes, calculated_entropies = active_learning.calculate_entropies(predictions)

        # Then
        self.assertTrue(numpy.equal(expected_votes, calculated_votes).all())
        self.assertTrue(numpy.isclose(expected_entropies, calculated_entropies, atol=0.001).all())

    def test_weighed_sampling(self):
        # Given
        entropies = [1, 3, 10, 4, 5, 6, 10, 7, 4, 3, 2, 5, 6, 9, 10, 2, 3, 4, 6, 8, 4]
        sampling_weight = 3
        possible_sample_indexes = [2, 6, 14]

        # When
        sample_index = active_learning.get_weighed_sample(entropies, sampling_weight)

        # Then
        self.assertTrue(sample_index in possible_sample_indexes)
