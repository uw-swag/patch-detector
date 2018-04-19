import argparse
import json

import sys

import active_learning


def run_active_learning_rounds(config):

    # load results
    calculated_features = json.load(config.features)
    vulnerable_versions = active_learning.get_versions_from_file(config.vulnerable_versions)

    print("Classifier;Rounds;Precision;Recall;F-score;Support;Accuracy;Next version;Entropy;Classification;")

    # run active learning for all classifier types
    for classifier in ["d_tree", "nb", "svm"]:
        training_versions = list(config.training_versions)
        run_active_learning_with_classifier(calculated_features, vulnerable_versions, training_versions, classifier)

    # json.dump(calculated_features, config.results, sort_keys=True, indent=4)


def run_active_learning_with_classifier(calculated_features, vulnerable_versions, training_versions, classifier):
    """
        Run active learning algorithm with specified parameters
    :param dict calculated_features: dictionary with features to be used in the model
    :param list of str vulnerable_versions: list of known vulnerable versions to be evaluated on active learning rounds
    :param list of str training_versions: initial versions to be inserted into the training model
    :param str classifier: what type of classifier to be run (d_tree, nb or svm)
    """
    rounds = 0

    while len(calculated_features) > len(training_versions) and rounds < 100:
        not_vulnerable_metrics, vulnerable_metrics, next_train_version, next_train_version_entropy, classification = \
            active_learning.active_learning_prediction(calculated_features,
                                                       vulnerable_versions,
                                                       training_versions,
                                                       classifier)
        rounds += 1
        precision = vulnerable_metrics[0]
        recall = vulnerable_metrics[1]
        fscore = vulnerable_metrics[2]
        support = vulnerable_metrics[3]
        accuracy = vulnerable_metrics[4]
        print("{};{};{};{};{};{};{};{};{};{};".format(
            classifier,
            rounds,
            precision,
            recall,
            fscore,
            support,
            accuracy,
            next_train_version,
            next_train_version_entropy,
            classification))
        training_versions.append(next_train_version)


def process_arguments():
    parser = argparse.ArgumentParser(
        description='''
            From a results file with features and a golden set of vulnerable versions, evaluates vulnerabilities
            using several active learning rounds.
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
    run_active_learning_rounds(config)


if __name__ == '__main__':
    main()
