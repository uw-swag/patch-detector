import argparse
import json
import sys

import numpy

import active_learning


def run_passive_learning(config):
    # load results
    calculated_features = json.load(config.features)
    vulnerable_versions = active_learning.get_versions_from_file(config.vulnerable_versions)

    print("Classifier;Rounds;Precision;Recall;F-score;Support;Accuracy;Next version;Entropy;")

    # run active learning for all classifier types
    for classifier in ["d_tree", "nb", "svm"]:
        training_versions = list(config.training_versions)
        run_passive_learning_with_classifier(calculated_features, vulnerable_versions, training_versions, classifier)

    return calculated_features


def run_passive_learning_with_classifier(calculated_features, vulnerable_versions, training_versions, classifier="d_tree"):
    """
        Run active learning algorithm with specified parameters
    :param dict calculated_features: dictionary with features to be used in the model
    :param list of str vulnerable_versions: list of known vulnerable versions to be evaluated on active learning rounds
    :param list of str training_versions: initial versions to be inserted into the training model
    :param str classifier: what type of classifier to be run (d_tree, nb or svm)
    """

    # build initial training set
    # build oracle set

    # Setup data for model
    features_train = []
    labels_train = []
    features_test = []
    labels_test = []
    versions_test = []

    # Get all features keys to compose array of features values
    feature_keys = sorted(calculated_features[training_versions[0]]["overall"].keys())

    for version, feature_item in calculated_features.items():

        feature_values = [feature_item["overall"][key] for key in feature_keys]

        if version in training_versions:
            features_train.append(feature_values)
            labels_train.append(version in vulnerable_versions)
        else:
            features_test.append(feature_values)
            labels_test.append(version in vulnerable_versions)
            versions_test.append(version)

    rounds = 0

    # loop
    #   run predictions
    #   pop from oracle and add labeled to training

    while len(calculated_features) > len(training_versions) and rounds < 100:
        np_features_train = numpy.array(features_train)
        np_features_test = numpy.array(features_test)

        not_vulnerable_metrics, vulnerable_metrics, next_version_index, committee_prediction, entropies = \
            passive_learning_prediction(np_features_train,
                                        labels_train,
                                        np_features_test,
                                        labels_test,
                                        classifier)

        # Get next training version and append to training data
        next_train_version = versions_test[next_version_index]
        next_train_version_entropy = entropies[next_version_index]
        features_train.append(features_test[next_version_index])
        labels_train.append(committee_prediction[next_version_index])

        rounds += 1
        precision = vulnerable_metrics[0]
        recall = vulnerable_metrics[1]
        fscore = vulnerable_metrics[2]
        support = vulnerable_metrics[3]
        accuracy = vulnerable_metrics[4]
        print("{};{};{};{};{};{};{};{};{};".format(
            classifier,
            rounds,
            precision,
            recall,
            fscore,
            support,
            accuracy,
            next_train_version,
            next_train_version_entropy))


def passive_learning_prediction(features_train, labels_train, features_test, labels_test, classifier="d_tree"):
    """
        Using train labels from file, predicts if versions in from result features are vulnerable using calculated features.
        Input dictionary is modified to add "vulnerable" key (bool)

    :param numpy.array features_train: array with features to train the classifiers
    :param list of int labels_train: list of labels to train the classifiers
    :param numpy.array features_test: array with features to be classified
    :param list of int labels_test: list of labels (oracle) to evaluate predictions
    :param str classifier: the classifier type to be used in the committee. Valid values: "d_tree", "nb", "svm"
    :return: current metrics and next version information
    :rtype: (list of float, list of float, int, list of int, list of float)
    """

    committee_prediction, entropies = active_learning.committee_classify(features_train, labels_train, features_test, classifier)
    not_vulnerable_metrics, vulnerable_metrics = active_learning.calculate_metrics(labels_test, committee_prediction)

    # Get next training version from weighted sample
    next_version_index = active_learning.get_weighed_sample(entropies)

    # Return next version to be inserted into the training model
    return not_vulnerable_metrics, vulnerable_metrics, next_version_index, committee_prediction, entropies


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
        '--vulnerable-versions',
        type=argparse.FileType('r'),
        required=True,
        metavar='path',
        help='The file path with a list of vulnerable versions to be used in the active learning process'
    )

    parser.add_argument(
        '--training-versions',
        type=str,
        required=True,
        nargs='+',
        metavar='VERSION_1 VERSION_2 ... VERSION_N',
        help='Versions to be used as training data from the oracle'
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

    calculated_features = run_passive_learning(config)

    if calculated_features:
        json.dump(calculated_features, config.results, sort_keys=True, indent=4)


if __name__ == '__main__':
    main()
