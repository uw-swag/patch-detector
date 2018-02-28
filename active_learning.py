import json
import numpy
from sklearn.naive_bayes import GaussianNB


def determine_vulnerability_status(results, labels_file):
    """
        Using train labels from file, predicts if versions in results are vulnerable using calculated features.
        Input dictionary is modified to add "vulnerable" key (bool)
    :param dictionary results: structured calculated features for all assessed versions
    :param {read} labels_file: the json file stream
    :return: probabilities of each prediction
    :rtype: numpy.array
    """
    # Read versions labels file
    golden_labels = get_versions_labels(labels_file)

    # Setup data for model
    features_train, labels_train, features_test, versions_test = preprocess_results(results, golden_labels)

    # Train and fit model
    clf = GaussianNB()
    clf.fit(features_train, labels_train)

    # Get predictions
    prediction = clf.predict(features_test)

    # Evaluate results
    for index, version in enumerate(versions_test):
        results[version]["vulnerable"] = bool(prediction[index])

    # Return probabilities
    return clf.predict_proba(features_test)


def get_versions_labels(json_file):
    """
        Reads versions labels from a json file to a dictionary.
    :param {read} json_file: the json file stream
    :return: A dictionary with versions and vulnerability state: 1 = vulnerable, 0 = not vulnerable
    :rtype: {str : int}
    """

    versions_labels = json.load(json_file)

    for version in versions_labels:
        if versions_labels[version] == "vulnerable":
            versions_labels[version] = 1
        else:
            versions_labels[version] = 0

    return versions_labels


def preprocess_results(results, labels):
    """
        Get results into a numpy array of versions x features
    :param {} results: dictionary structure with calculated feature values for assessed versions
    :param {} labels: labels for train data
    :return: a tuple with train features, train labels, test features, test versions
    :rtype: (numpy.array, list of str, numpy.array, list of str)
    """

    features_train = []
    labels_train = []
    features_test = []
    versions_test = []

    for key, value in results.items():

        feature = [value["overall"]["common_additions"],
                   value["overall"]["common_deletions"],
                   value["overall"]["patch_additions"],
                   value["overall"]["patch_additions_score"],
                   value["overall"]["patch_deletions"],
                   value["overall"]["patch_deletions_score"],
                   value["overall"]["version_additions"],
                   value["overall"]["version_additions_score"],
                   value["overall"]["version_deletions"],
                   value["overall"]["version_deletions_score"]]

        if key in labels:
            features_train.append(feature)
            labels_train.append(labels[key])
        else:
            features_test.append(feature)
            versions_test.append(key)

    return numpy.array(features_train), labels_train, numpy.array(features_test), versions_test
