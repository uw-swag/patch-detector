#!/patch-detector/venv/bin python

import argparse
import json
import os
import random
import shutil
import sys

import git

import detector
import mongo_handler
import rabbitMQ_handler
import runner


def consume(github_address, vulnerability_id, commit_hashes, persister, versions=None):
    """
        Consume information from a patch_detection task (message from RabbitMQ queue) to run patch_detector and
        save results with persister.
    :param github_address: github repository address
    :param vulnerability_id: the ID of the vulnerability
    :param commit_hashes: list of commit hashes from github to extract patches for evaluation
    :param persister: function to save results with signature handle(str: commit_hash, dict: patch_detector_results)
    :param versions: selected tags on github to be evaluated. If None provided, all tags are evaluated.
    """
    # 1. Clone git repo
    temp_folder = "temp_folder_" + str(random.randint(0, sys.maxsize))
    temp_patch_filename = "temp_file_" + str(random.randint(0, sys.maxsize)) + ".patch"
    repo = git.Repo.clone_from(github_address, temp_folder)

    # 2. Process all given commit hashes
    for commit_hash in commit_hashes:

        # 3. Get patch from hash
        try:
            patch = repo.git.show(commit_hash)

            with open(temp_patch_filename, "w") as patch_file:
                patch_file.write(patch)

        except git.GitCommandError:
            # Just ignore hash error
            print("Warning: commit hash {} not found.".format(commit_hash))
            continue

        # 4. Create config object
        args = [temp_patch_filename, repo.working_dir]
        config = runner.process_arguments(args)
        config.versions = versions

        # 5. Run evaluation
        version_results = runner.run_git(config, detector.run)
        runner.determine_vulnerability_status(config, version_results)

        # 6. Save to database
        persister(github_address, vulnerability_id, commit_hash, version_results)

    # 7. Delete temp resources
    shutil.rmtree(temp_folder)
    os.remove(temp_patch_filename)


def unpack_message(message):
    # Example of message
    # message = {"repo_address": "http://github.com",
    #            "commits": ["asdfsdg", "afdgsfgrgdfs", "ghhgfdasdgfh"],
    #            "vulnerability_id": "CVE-001",
    #            "versions": ["1.0.0", "2.0.0"]}

    github_address = message["repo_address"]
    commit_hashes = message["commits"]
    vulnerability_id = message["vulnerability_id"]
    versions = ",".join(message["versions"]) if ("versions" in message and len(message["versions"]) > 0) else None

    return github_address, commit_hashes, vulnerability_id, versions


def process_arguments():
    parser = argparse.ArgumentParser(
        description='''
            Run patch_detector listening to messages from RabbitMQ and storing to MongoDB
        '''
    )

    parser.add_argument(
        '--config',
        default='config.json',
        type=argparse.FileType('r'),
        metavar='path',
        help='JSON config file'
    )

    parser.add_argument(
        '--single-run',
        nargs='*',
        metavar='parameter',
        help='Perform a single run locally with given parameters vulnerability_id repo_address commit VERSION_1 ... VERSION_N'
    )

    return parser.parse_args()


def listen_messages():

    rabbitmq_host = config["rabbitmq_host"]
    rabbitmq_username = config["rabbitmq_username"]
    rabbitmq_password = config["rabbitmq_password"]
    rabbitmq_queue = config["rabbitmq_queue"]

    mongodb_host = config["mongodb_host"]
    mongodb_username = config["mongodb_username"]
    mongodb_password = config["mongodb_password"]
    mongodb_database = config["mongodb_database"]

    # Persister call
    def persist_to_mongo(github_address, vulnerability_id, commit_hash, results):
        mongo_handler.save_vulnerability_results(mongodb_host, mongodb_username, mongodb_password, mongodb_database,
                                                 github_address, vulnerability_id, commit_hash, results)

    # Consumer call
    def handle_message_body(body):
        received_msg = json.loads(body)
        print("Dequeued message {}".format(received_msg))

        github_address, commit_hashes, vulnerability_id, versions = unpack_message(received_msg)
        consume(github_address, vulnerability_id, commit_hashes, persist_to_mongo, versions)

        return True

    rabbitMQ_handler.listen_messages(rabbitmq_host, rabbitmq_username, rabbitmq_password, rabbitmq_queue,
                                     handle_message_body)


def single_run(args):

    def persister(github_address, vulnerability_id, commit_hash, results):
        print(results)

    vulnerability_id = args.single_run[0]
    repo_address = args.single_run[1]
    commit_hashes = [args.single_run[2]]
    versions = args.single_run[3:]
    versions = ",".join(versions) if (versions is not None and len(versions) > 0) else None

    consume(repo_address, vulnerability_id, commit_hashes, persister, versions)


if __name__ == '__main__':

    args = process_arguments()
    config = json.load(args.config)

    if args.single_run:
        single_run(args)
    else:
        listen_messages(config)
