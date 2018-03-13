import argparse
import json

import sys

import active_learning


def run_active_learning_rounds(config):

    # get oracle
    # with open(config.oracle, 'r') as versions_file:
    #     oracle = active_learning.get_versions_labels(versions_file)

    #load results
    calculated_features = json.load(config.features)
    oracle_versions = active_learning.get_versions_labels(config.oracle)
    accuracy = 0
    rounds = 0

    while len(calculated_features) > len(config.training_versions) and accuracy < 0.9:

        accuracy, next_train_version = active_learning.determine_vulnerability_status(calculated_features,
                                                                                      oracle_versions,
                                                                                      config.training_versions)
        rounds += 1
        print("Rounds: {}; Accuracy: {}; Next: {}".format(rounds, accuracy, next_train_version))
        config.training_versions.append(next_train_version)

    json.dump(calculated_features, config.results, sort_keys=True, indent=4)

    pass

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
        '--oracle',
        type=argparse.FileType('r'),
        required=True,
        metavar='path',
        help='The oracle to be used as truth values when calculating model accuracy'
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

    print("Processing file {} with training versions {} and oracle {} ...".format(config.features, config.training_versions, config.oracle))

    run_active_learning_rounds(config)
    # processed_results = json.load(config.features)
    #
    # next_version = determine_vulnerability_status(processed_results, config.versions_labels)
    #
    # if processed_results:
    #     json.dump(processed_results, config.results, sort_keys=True, indent=4)
    #
    # print("\n\nNext version to be inserted in the training model: {}".format(next_version))


if __name__ == '__main__':
    main()
