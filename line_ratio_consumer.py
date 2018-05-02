import os
import random
import shutil
import sys

import git

import detector
import runner


def consume(github_address, commit_hashes, versions=[]):

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
        print(version_results)

    # 7. Delete temp resources
    shutil.rmtree(temp_folder)
    os.remove(temp_patch_filename)


# Example
consume("https://github.com/uw-swag/patch-detector.git",
         ["2daedbcb53cccfdf22d24dbff2e10312a179ea72","878be37af5644fcfabb12babe253283f7de4cfee"],
         "1.0.0")
