import argparse
import json

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure


def wrap_mongo_objects(repo_address, vulnerability_id, patch_commit_hash, patch_evaluation_results):
    """
        Converts patch detector results into objects insertable into a MongoDB. Objects can be identified by
        (repo_address, vulnerability_id, patch_commit_hash).
    :param repo_address: github repository address
    :param vulnerability_id: an ID such as CVE-0001
    :param patch_commit_hash: the commit hash from github
    :param patch_evaluation_results: the results dict object from patch_detector
    :return: MongoDB objects
    :rtype: list of dict
    """
    objs = []

    for version, results in patch_evaluation_results.items():

        breakdown = results["breakdown"]
        new_breakdown = []
        for file, stats in breakdown.items():
            file_stats = stats
            file_stats["file"] = file
            new_breakdown.append(file_stats)
        results["breakdown"] = new_breakdown

        obj = {"repository": repo_address, "version": version, "vulnerability_id": vulnerability_id,
               "commit": patch_commit_hash,
               "results": results}
        objs.append(obj)

    return objs


def save_vulnerability_results(host, username, password, database, repo_address, vulnerability_id, patch_commit_hash,
                               patch_evaluation_results):
    client = MongoClient("mongodb://{}:{}@{}:27017".format(username, password, host))
    db = client[database]

    try:
        # The ismaster command is cheap.
        client.admin.command('ismaster')
    except ConnectionFailure:
        print("Mongo server not available")
        return False

    collection = db.vulnerabilities

    mongo_objects = wrap_mongo_objects(repo_address, vulnerability_id, patch_commit_hash, patch_evaluation_results)

    if mongo_objects and len(mongo_objects) > 0:
        insert_result = collection.insert_many(mongo_objects)

        success = len(insert_result.inserted_ids) > 0

        if success:
            print("Persisted vulnerability {} with hash {}".format(vulnerability_id, patch_commit_hash))
    else:
        print("Nothing persisted from vulnerability {} with hash {}".format(vulnerability_id, patch_commit_hash))
        success = True

    return success


def process_arguments():
    parser = argparse.ArgumentParser(
        description='''
            MongoDB persister
        '''
    )

    parser.add_argument(
        '--config',
        default='config.json',
        type=argparse.FileType('r'),
        metavar='path',
        help='JSON config file'
    )

    return parser.parse_args()


def main():

    args = process_arguments()
    config = json.load(args.config)

    host = config["mongodb_host"]
    username = config["mongodb_username"]
    password = config["mongodb_password"]
    database = config["mongodb_database"]

    # Usage example of saving to MongoDB
    vulnerability_results = {
        '1.0.0': {'overall': {'additions': 0.0, 'deletions': 0.3333333333333333, 'confident': True}, 'breakdown': {
            'runner.py': {'additions': 0.0, 'deletions': 0.3333333333333333, 'status': 'unchanged'}},
                  'vulnerable': True},
        '2.0.0': {'overall': {'additions': 0.0, 'deletions': 0.0, 'confident': True},
                  'breakdown': {'runner.py': {'additions': 0.0, 'deletions': 0.0, 'status': 'unchanged'}},
                  'vulnerable': True}}

    save_vulnerability_results(host, username, password, database,
                               "repo_git", "NVD-001", "hash1", vulnerability_results)

    # Checking saved results
    client = MongoClient("mongodb://{}:{}@{}:27017".format(username, password, host))
    db = client[database]

    try:
        # The ismaster command is cheap.
        client.admin.command('ismaster')
    except ConnectionFailure:
        print("Server not available")

    collection = db.vulnerabilities

    for obj in collection.find():
        print("{};{};{}".format(obj["vulnerability_id"], obj["version"], obj["results"]["vulnerable"]))


if __name__ == '__main__':
    main()
