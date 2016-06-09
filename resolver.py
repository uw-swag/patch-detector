#!/usr/bin/env python3

import os

import git


def resolve_path(repo, first, second, path, debug=False):
    first = repo.commit(first)
    second  = repo.commit(second)

    blob_path = True
    tree = first.tree
    for path_element in path.split(os.path.sep):
        try:
            tree = tree[path_element]
        except KeyError:
            blob_path = False
            break

    if not blob_path:
        raise Exception('Path does not exist in start object')

    blob_path = tree.path

    for diff in first.diff(second):
        if diff.a_path == blob_path:
            if diff.deleted_file:
                blob_path = 'deleted'
            else:
                blob_path = diff.b_path

            break

    return blob_path

if __name__ == '__main__':
    import sys

    print(resolve_path(
        git.Repo(sys.argv[1]),
        sys.argv[2],
        sys.argv[3],
        sys.argv[4],
        True
    ))