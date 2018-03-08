import argparse
import json
import random
import numpy
import sys
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier


def determine_vulnerability_status(results, labels_file):
    """
        Using train labels from file, predicts if versions in results are vulnerable using calculated features.
        Input dictionary is modified to add "vulnerable" key (bool)
    :param dictionary results: structured calculated features for all assessed versions
    :param {read} labels_file: the json file stream
    :return: next version to be inserted in the training model (smaller certainty)
    :rtype: str
    """
    # Read versions labels file
    golden_labels = get_versions_labels(labels_file)

    # Setup data for model
    features_train, labels_train, features_test, versions_test = preprocess_results(results, golden_labels)

    n_classifiers = 5  # number of classifiers

    classifiers = []
    predictions = []

    for i in range(n_classifiers):
        # Train and fit model
        # clf = MultinomialNB()

        # Train and fit model
        clf = DecisionTreeClassifier(criterion="entropy", splitter="random", random_state=random.randint(0, 2**32-1))
        clf.fit(features_train, labels_train)

        # Get predictions
        predictions.append(clf.predict(features_test).tolist())

        classifiers.append(clf)

    votes, entropies = calculate_entropies(numpy.array(predictions))

    # Evaluate results
    next_train_version = None
    for index, version in enumerate(versions_test):
        results[version]["vulnerable"] = bool(votes[index])
        results[version]["entropy"] = entropies[index]

        # Get version with highest entropy
        if not next_train_version or results[version]["entropy"] > results[next_train_version]["entropy"]:
            next_train_version = version

    # Keep training labels in results too
    for version_key, value in golden_labels.items():
        results[version_key]["vulnerable"] = bool(value)
        results[version_key]["entropy"] = 0.0

    # Return next version to be inserted into the training model
    return next_train_version


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


def calculate_entropies(predictions):
    """
        This entropy calculates the disagreement ratio between classifiers (entropy), and classifies with the majority
        of votes from all classifiers.
    :param numpy.array predictions: the numpy array with predictions form all classifiers in the shape (n_classifiers x data points)
    :return: a tuple with the classification from the majority of classifiers and respective entropies
    :rtype: (numpy.array, numpy.array)
    """
    n_classifiers = predictions.shape[0]
    positive_counts = predictions.sum(axis=0)

    positive_ratio = positive_counts * numpy.full(positive_counts.shape, 1/n_classifiers)
    negative_ratio = numpy.ones(positive_counts.shape) - positive_ratio

    # Using numpy.ma (Masked arrays) to avoid NaN with log2(0)
    # Entropy formula: H(X) = -1 * sum(P(xi)*log2(Pxi))
    # https://en.wikipedia.org/wiki/Entropy_(information_theory)
    entropies = numpy.negative(positive_ratio * numpy.ma.log2(positive_ratio).filled(0) +
                               negative_ratio * numpy.ma.log2(negative_ratio).filled(0))
    votes = (positive_ratio > negative_ratio)

    return votes, entropies


def process_arguments():
    parser = argparse.ArgumentParser(
        description='''
            From a results file with features, evaluates vulnerabilities using 
            supervised machine learning.
        '''
    )

    parser.add_argument(
        '--features',
        type=argparse.FileType('r'),
        required=True,
        metavar='path',
        help='Features values to be evaluated'
    )

    parser.add_argument(
        '--versions-labels',
        default=None,
        type=argparse.FileType('r'),
        metavar='path',
        help='Path to the json file with active learning training data with format { "version" : "vulnerable|not '
             'vulnerable"} '
    )

    parser.add_argument(
        '--results',
        type=argparse.FileType('w+'),
        default=sys.stdout,
        help='Path to store the results'
    )

    return parser.parse_args()


def main():
    config = process_arguments()

    print("Processing file {} with training versions {} ...".format(config.features, config.versions_labels))

    processed_results = json.load(config.features)

    next_version = determine_vulnerability_status(processed_results, config.versions_labels)

    if processed_results:
        json.dump(processed_results, config.results, sort_keys=True, indent=4)

    print("\n\nNext version to be inserted in the training model: {}".format(next_version))


if __name__ == '__main__':
    main()

