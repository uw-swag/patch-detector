# patch-detector

A tool for detecting vulnerabilities in different versions of a software project. Given a fixing patch, this tool searches for similarities from vulnerable and fixed code in all tagged versions in a git repository.

## Detection methods

### Line ratios

This method compares deleted and added lines from the patch to a version. If the assessed version reaches certain thresholds of non-communality with deleted lines and communality with added lines, it is marked as _non-vulnerable_. If the inverse of commonality is found (communality with deleted lines and non-communality with added lines), it is marked as _vulnerable_. Otherwise it is marked as indeterminate. 

The goal of this method is to achieve a high precision and recall rates of __non-vulnerable__ versions, i.e. be sure that a version labeled as _non-vulnerable_ is indeed not vulnerable to that vulnerability. In the other hand, this method has a conservative approach by labelling a version as _vulnerable_ when it's uncertain about the version's status.

### Active learning

This methods is based on supervised machine-learning techniques such as Naïve Bayes, Support Vector Machines or Decision Trees. A model is initially trained based on the two adjacent versions from the given patch. The version right before the patch is labeled _vulnerable_ and the version right after the patch (fixed) is labeled _non-vulnerable_. Based on features such as code tokens n-grams, the model suggests the most confusing version to be labeled by the developer (i.e., the most uncertain version). With the proper label, this suggested version in added to the training dataset, and the model is retrained. This iteration proceeds in several rounds until the desired precision is met.

The goal of this method is to achieve high precision and recall rates of __vulnerable__ versions, i.e. be sure that a version labeled _vulnerable_ is indeed vulnerable to that vulnerability. In the other hand, as the intent of this method is to help developers find vulnerable versions of their software, this method is an attempt to minimize false positives in vulnerable versions. Therefore, it might miss some true positives.

## How to run

### Requirements

Install python, pip and and virtual environment with dependencies described on requirements.txt. Instructions for that are available at
https://packaging.python.org/guides/installing-using-pip-and-virtualenv/.

Install and configure RabbitMQ as per https://www.rabbitmq.com/download.html.

### Running

This will run the line ratios method for the given patch to all tagged versions in the git repo at the give project folder.

```console
python runner.py --method line_ratios PATCH_FILE_PATH PROJECT_FOLDER_PATH
```

This will run the active learning method with the oracle for vulnerable versions at the given file path (a list of strings with versions tags) and the two initial versions for the training model.

```console
python runner.py --method active_learning --vulnerable-versions VULNERABLE_VERSIONS_FILE_PATH --training-versions VERSION_1 VERSION_2 PATCH_FILE_PATH PROJECT_FOLDER_PATH
```

For a complete list of options:

```console
python runner.py -h
```

## Experiments

All experiments data and results can be found under the `experiments` folder. To replicate experiments, simply run the `run_experiments.sh` script.
