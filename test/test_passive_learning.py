import unittest
import os
import active_learning
import passive_learning
import numpy


class TestPassiveLearning(unittest.TestCase):
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
        self.vulnerable_versions = ["acra-4.3.1"]
        self.test_file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'versions.txt')

    def tearDown(self):
        pass

    def test_passive_learning(self):
        # Given
        training_versions = ["acra-4.3.1", "acra-4.4.0"]
        assessed_version = "Acra-5.0.2"
        expected_not_vulnerable_metrics = [0, 0, 0, 1, 0]
        expected_vulnerable_metrics = [0, 0, 0, 0, 0]
        expected_next_train_version = "Acra-5.0.2"
        expected_next_train_version_entropy = 0.0

        # When
        with open(self.test_file_path, 'r') as versions_file:
            vulnerable_versions = active_learning.get_versions_from_file(versions_file)
        nv_metrics, v_metrics, next_train_version, next_train_version_entropy = passive_learning.run_passive_learning_with_classifier \
            (self.features,
             vulnerable_versions,
             training_versions)

        # Then
        self.assertTrue(self.features[assessed_version]["vulnerable"])
        self.assertEqual(self.features[assessed_version]["entropy"], 0.0)
        self.assertListEqual(nv_metrics, expected_not_vulnerable_metrics)
        self.assertListEqual(v_metrics, expected_vulnerable_metrics)
        self.assertEqual(next_train_version, expected_next_train_version)
        self.assertEqual(next_train_version_entropy, expected_next_train_version_entropy)
