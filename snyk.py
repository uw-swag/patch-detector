import argparse
import json
import rabbitMQ_handler


def process_arguments():
    parser = argparse.ArgumentParser(
        description='''
            Handle SNYK data
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
        '--file',
        type=argparse.FileType('r'),
        required=True,
        metavar='path',
        help='JSON SNYK data file'
    )

    return parser.parse_args()


if __name__ == '__main__':

    args = process_arguments()

    config = json.load(args.config)

    host = config["rabbitmq_host"]
    username = config["rabbitmq_username"]
    password = config["rabbitmq_password"]
    queue = config["rabbitmq_queue"]

    snyk_data = json.load(args.file)

    for item in snyk_data:
        for vulnerability in snyk_data[item]:

            snyk_id = vulnerability["id"]

            # Some vulnerabilities don't have a CVE
            cve_id = vulnerability["identifiers"]["CVE"][0] if len(vulnerability["identifiers"]["CVE"]) > 0 else ""

            repo_address = ""
            commit_hashes = []

            for ref in vulnerability["references"]:
                if "commit" in ref["url"]:

                    # Get git repo url and commit hash separately.
                    # Pull requests with multiple commits have "commits" on the address
                    url_parts = ref["url"].split("/commits/");
                    if len(url_parts) < 2:
                        url_parts = ref["url"].split("/commit/");

                    # Remove pull request suffix, if there
                    repo_address = url_parts[0].split("/pull/")[0]
                    commit_hashes.append(url_parts[1])

            # Send message to processing queue
            if repo_address != "" and len(commit_hashes) > 0:
                message = {'repo_address': repo_address + ".git", 'commits': commit_hashes,
                           'vulnerability_id': snyk_id, 'versions': [], "cve_id": cve_id}

                rabbitMQ_handler.send_message(host, username, password, queue, message)
                print("Sent {};{};{};{}".format(snyk_id, cve_id, repo_address + ".git", commit_hashes))
