import chardet
import javalang
import os

from sklearn.feature_extraction.text import CountVectorizer


def get_n_grams(java_lines):
    cv = CountVectorizer(stop_words=None, analyzer="word", token_pattern=None, tokenizer=tokenize, preprocessor=None,
                         ngram_range=(4, 4), lowercase=False)
    cv.fit_transform(java_lines)

    return cv.get_feature_names()


def tokenize(java_code):
    """
        Return a list of tokens from a java code
    :param str java_code: the java code to be tokenized
    :return: a list of tokens
    :rtype: list of str
    """
    tokens = list(javalang.tokenizer.tokenize(java_code))
    return list(map(lambda x: x.value, tokens))


def similarity_scores(old_code, new_code):
    """
        Calculate similarity score between old code and new code
    :param list[str] old_code: list of old java lines of code (strings)code
    :param list[str] new_code: list of new java lines of code (strings)
    :return: a tuple (old similarity score, new similarity score)
    :rtype: (float, float)
    """
    common_n_grams, old_n_grams, new_n_grams = commonalities(old_code, new_code)
    old_score = common_n_grams / old_n_grams if old_n_grams else 0
    new_score = common_n_grams / new_n_grams if new_n_grams else 0
    return old_score, new_score


def commonalities(old_code, new_code):
    """
        Gets common n-grams between old code and new code
    :param list[str] old_code: list of old java lines of code (strings)code
    :param list[str] new_code: list of new java lines of code (strings)
    :return: a tuple (common n-grams, old n-grams, new n-grams)
    :rtype: (int, int, int)

    """
    common_n_grams = 0
    old_n_grams = 0
    new_n_grams = 0

    if len(old_code) > 0:
        cv_old = CountVectorizer(stop_words=None, analyzer="word", token_pattern=None, tokenizer=tokenize,
                                 preprocessor=None, ngram_range=(4, 4), lowercase=False)

        try:
            cv_old.fit(["\n".join(old_code)])
            old_n_grams = len(cv_old.get_feature_names())
            common_n_grams = cv_old.transform(["\n".join(new_code)]).nnz
        except ValueError:
            # Maybe there are no valid java tokens in this code, so keep it as zero
            pass

        # Common n-grams are shared between both old and new, it doesn't matter which one is transformed
        # as the result should be the same.

    if len(new_code) > 0:
        cv_new = CountVectorizer(stop_words=None, analyzer="word", token_pattern=None, tokenizer=tokenize,
                                 preprocessor=None, ngram_range=(4, 4), lowercase=False)

        try:
            cv_new.fit(["\n".join(new_code)])
            new_n_grams = len(cv_new.get_feature_names())
        except ValueError:
            # Maybe there are no valid java tokens in this code, so keep it as zero
            pass

    return common_n_grams, old_n_grams, new_n_grams


def evaluate_version(config):
    from detector import blacklisted, whitelisted, split_changes, compare

    scores = {}
    total_common_deletions = 0
    total_version_deletions = 0
    total_patch_deletions = 0
    total_common_additions = 0
    total_version_additions = 0
    total_patch_additions = 0

    for diff in config.patch:
        new_source_path = os.path.join(config.project, diff.header.path)
        old_source_path = os.path.join(config.project, diff.header.old_path)

        full_path = os.path.abspath(new_source_path)
        if os.path.exists(full_path):
            if config.debug:
                print('Found {0}'.format(full_path))
        else:
            full_path = os.path.abspath(old_source_path)
            if os.path.exists(full_path):
                if config.debug:
                    print('WARNING: Found file at old path: {0}'.format(
                        full_path
                    ))

        if blacklisted(full_path) or not whitelisted(full_path):
            continue

        scores[diff.header.path] = {}
        version_deleted_lines = []
        version_added_lines = []

        patch_deletions, patch_additions, one_line_change, prev_line, next_line = split_changes(diff)

        if os.path.exists(full_path):

            with open(full_path, 'rb') as file:
                detection = chardet.detect(file.read())

            if config.debug:
                print('{0}: encoding is {1} with {2} confidence'.format(
                    full_path, detection['encoding'], detection['confidence']
                ))

            with open(full_path, 'r', encoding=detection['encoding']) as file:
                source = file.readlines()

                # In the case of a one line change, we also look for the lines
                # immediately preceding and following the changed line.
                if one_line_change:
                    for index, line in enumerate(source):
                        if line.strip() == prev_line.strip() and \
                                index + 2 < len(source) and \
                                source[index + 2].strip() == next_line.strip():
                            if patch_additions and compare(patch_additions[0], source[index + 1]):
                                version_added_lines.append(source[index + 1])
                                break
                            elif patch_deletions and not compare(patch_deletions[0], source[index + 1]):
                                version_deleted_lines.append(source[index + 1])
                                break
                else:

                    for addition in patch_additions:
                        for line in source:
                            if compare(addition, line):
                                version_added_lines.append(addition)
                                break

                    for deletion in patch_deletions:
                        found = False
                        for line in source:
                            if compare(deletion, line):
                                found = True
                                break

                        if not found:
                            version_deleted_lines.append(deletion)
        else:
            if config.debug:
                print('WARNING: File {0} does not exist'.format(full_path))

        deletion_scores = commonalities(version_deleted_lines, patch_deletions)
        addition_scores = commonalities(version_added_lines, patch_additions)

        total_common_deletions += deletion_scores[0]
        total_version_deletions += deletion_scores[1]
        total_patch_deletions += deletion_scores[1]
        total_common_additions += addition_scores[0]
        total_version_additions += addition_scores[1]
        total_patch_additions += addition_scores[2]

        scores[diff.header.path]['common_deletions'] = deletion_scores[0]
        scores[diff.header.path]['version_deletions'] = deletion_scores[1]
        scores[diff.header.path]['patch_deletions'] = deletion_scores[2]
        scores[diff.header.path]['version_deletions_score'] = deletion_scores[0] / deletion_scores[1] if \
            deletion_scores[1] > 0 else 0
        scores[diff.header.path]['patch_deletions_score'] = deletion_scores[0] / deletion_scores[2] if deletion_scores[
                                                                                                           2] > 0 else 0
        scores[diff.header.path]['common_additions'] = addition_scores[0]
        scores[diff.header.path]['version_additions'] = addition_scores[1]
        scores[diff.header.path]['patch_additions'] = addition_scores[2]
        scores[diff.header.path]['version_additions_score'] = addition_scores[0] / addition_scores[1] if \
            addition_scores[1] > 0 else 0
        scores[diff.header.path]['patch_additions_score'] = addition_scores[0] / addition_scores[2] if addition_scores[
                                                                                                           2] > 0 else 0
        scores[diff.header.path]['status'] = diff.header.status

        if total_patch_deletions == 0:
            version_deletions_score = 1.0
            patch_deletions_score = 1.0
        else:
            version_deletions_score = total_common_deletions / total_version_deletions if total_version_deletions > 0 else 0.0
            patch_deletions_score = total_common_deletions / total_patch_deletions

        if total_patch_additions == 0:
            versions_additions_score = 1.0
            patch_additions_score = 1.0
        else:
            versions_additions_score = total_common_additions / total_version_additions if total_version_additions > 0 else 0.0
            patch_additions_score = total_common_additions / total_patch_additions

    result = {
        'overall': {
            'version_deletions': total_version_deletions,
            'version_additions': total_version_additions,
            'patch_deletions': total_patch_deletions,
            'patch_additions': total_patch_additions,
            'common_deletions': total_common_deletions,
            'common_additions': total_common_additions,
            'version_deletions_score': version_deletions_score,
            'version_additions_score': versions_additions_score,
            'patch_deletions_score': patch_deletions_score,
            'patch_additions_score': patch_additions_score
        },
        'breakdown': scores
    }

    return result
