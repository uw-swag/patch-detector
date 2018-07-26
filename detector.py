#!/usr/bin/env python3

import argparse
import json
import os
import sys

import git
import yaml

import util

whitelist = set()
blacklist = ['test', 'tests', 'spec']

module_path = os.path.dirname(os.path.realpath(__file__))
resources_path = os.path.join(module_path, 'resources')

try:
    with open(os.path.join(resources_path, 'languages.yml'), 'r') as file:
        languages = yaml.load(file)
except FileNotFoundError:
    print('Missing `languages.yml\': https://github.com/github/linguist/blob/master/lib/linguist/languages.yml')
    sys.exit(1)

for key, value in languages.items():
    if 'extensions' in value:
        whitelist.update(value['extensions'])


def whitelisted(name):
    return any(name.lower().endswith(item) for item in whitelist)


def blacklisted(name):
    return any(item in name.lower() for item in blacklist)


def compare(first, second):
    return all(token in second.strip().split() for token in first.strip().split())


def run(config, version_diffs):
    total_patch_additions = 0
    total_patch_deletions = 0

    detected_patch_additions = 0
    detected_patch_deletions = 0

    ratios = {}

    confident = True

    for patch_diff in config.patch:
        new_source_path = patch_diff.header.path
        old_source_path = patch_diff.header.old_path

        full_path = new_source_path
        if full_path in [d.b_path for d in version_diffs]:
            if config.debug:
                print('Found {0}'.format(full_path))
        else:
            full_path = old_source_path
            if full_path in [d.b_path for d in version_diffs]:
                if config.debug:
                    print('WARNING: Found file at old path: {0}'.format(
                        full_path
                    ))

        if blacklisted(full_path) or not whitelisted(full_path):
            continue

        ratios[patch_diff.header.path] = {}

        detected_file_deletions = 0
        detected_file_additions = 0

        patch_deletions, patch_additions, _, _, _ = split_changes(patch_diff)

        found = False

        for version_diff in version_diffs:

            # b_path is the path that will become the fix_patch after applying the diff to the evaluated version
            if full_path == version_diff.b_path:

                found = True

                # Need to format the diff as a string parseable by whatthepatch
                stripped_changes = str(version_diff.diff).replace("b'", "", 1).replace("b\"", "", 1).replace("\\n", "\n")
                version_patch = "--- {}\n+++ {}\n{}".format(full_path, full_path, stripped_changes)

                version_diff_patch = util.load_patch(version_patch)

                version_deletions, version_additions, _, _, _ = split_changes(version_diff_patch[0])

                # Keep a search index so it always searches forward
                search_index = 0
                for deletion in patch_deletions:
                    for i in range(search_index, len(version_deletions)):
                        if deletion == version_deletions[i]:
                            search_index = i
                            detected_file_deletions += 1
                            break

                # Keep a search index so it always searches forward
                search_index = 0
                for addition in patch_additions:
                    for i in range(search_index, len(version_additions)):
                        if addition == version_additions[i]:
                            search_index = i
                            detected_file_additions += 1
                            break

                break

        if not found:
            if config.debug:
                print('WARNING: File {0} does not exist'.format(full_path))

        total_file_additions = len(patch_additions)
        total_file_deletions = len(patch_deletions)

        detected_patch_additions += detected_file_additions
        detected_patch_deletions += detected_file_deletions

        total_patch_additions += total_file_additions
        total_patch_deletions += total_file_deletions

        # Detected means things that are missing from the evaluated version.
        # So the ratio comes from the difference from the total (original).
        added_ratio = (total_file_additions - detected_file_additions) / total_file_additions if total_file_additions > 0 else None
        deleted_ratio = (total_file_deletions - detected_file_deletions) / total_file_deletions if total_file_deletions > 0 else None

        ratios[patch_diff.header.path]['additions'] = added_ratio
        ratios[patch_diff.header.path]['deletions'] = deleted_ratio
        ratios[patch_diff.header.path]['status'] = patch_diff.header.status

    result = {
        'overall': {
            'additions': (total_patch_additions - detected_patch_additions) / total_patch_additions if total_patch_additions > 0 else None,
            'deletions': (total_patch_deletions - detected_patch_deletions) / total_patch_deletions if total_patch_deletions > 0 else None,
            'confident': confident
        },
        'breakdown': ratios
    }

    return result


def split_changes(diff, keep_unchanged=False):
    """
        Splits a diff object into deletions (or old code) and additions (or new code)
    :param diff: the diff object (header, changes, text)
    :param keep_unchanged: if True, returns the old and new blocks of code
    :return: the tuple (deleted lines, added lines, one-line change?, previous line,, next line)
    :rtype: (list of str, list of str, bool, str, str)
    """
    raw_additions = []
    raw_deletions = []
    prev_line = None
    next_line = None

    for index, change in enumerate(diff.changes):
        # Ignore empty or whitespace lines
        if not change[2] or change[2].isspace():
            continue
        # line was unchanged
        elif change[0] == change[1]:
            if keep_unchanged:
                raw_deletions.append(change[2])
                raw_additions.append(change[2])
            continue
        # line was changed, content is the same
        elif change[0] and change[1] and change[0] != change[1]:
            if keep_unchanged:
                raw_deletions.append(change[2])
                raw_additions.append(change[2])
            continue
        # line was inserted
        elif not change[0] and change[1]:
            raw_additions.append(change[2])

            # keep track of the lines before and after each change
            if index > 0:
                prev_line = diff.changes[index - 1][2]
            if index < len(diff.changes) - 1:
                next_line = diff.changes[index + 1][2]
        # line was removed
        elif change[0] and not change[1]:
            raw_deletions.append(change[2])

            # keep track of the lines before and after each change
            if index > 0:
                prev_line = diff.changes[index - 1][2]
            if index < len(diff.changes) - 1:
                next_line = diff.changes[index + 1][2]
        # should never happen
        else:
            print('WARNING: Could not detect change type')
            raise Exception(change)

    deletions = list(filter(lambda x: x not in raw_additions, raw_deletions)) if not keep_unchanged else raw_deletions
    additions = list(filter(lambda x: x not in raw_deletions, raw_additions)) if not keep_unchanged else raw_additions

    one_line_change = len(raw_additions) + len(raw_deletions) == 1

    return deletions, additions, one_line_change, prev_line, next_line


def process_arguments():
    parser = argparse.ArgumentParser(
        description='''
            Run detector algorithm for a given patch on a given version.
        '''
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Turn on debugging'
    )

    parser.add_argument(
        '--version',
        help='Version to be evaluated'
    )

    parser.add_argument(
        '--fix-hash',
        help='Patch commit hash'
    )

    parser.add_argument(
        'patch',
        type=argparse.FileType('r'),
        help='Path to the patch to be tested'
    )

    parser.add_argument(
        'project',
        help='Path to the root of the project source code'
    )

    return parser.parse_args()


def main():
    config = process_arguments()

    repo = git.Repo(config.project)
    commit = repo.commit(config.version)
    diff = commit.diff(config.fix_hash, create_patch=True)

    config.patch = util.load_patch(config.patch.read())
    print(json.dumps(run(config, diff), indent=4))


if __name__ == '__main__':
    main()
