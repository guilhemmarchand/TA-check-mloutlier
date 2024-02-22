#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

# Standard library imports
import os
import sys
import time
import logging
from logging.handlers import RotatingFileHandler

# Networking and URL handling imports
from urllib.parse import urlencode
import urllib3

# Disable insecure request warnings for urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# splunk home
splunkhome = os.environ["SPLUNK_HOME"]

# appebd lib
sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-check-mloutlier", "lib"))

# import Splunk libs
import splunklib.results as results

# logging:
# To avoid overriding logging destination of callers, the libs will not set on purpose any logging definition
# and rely on callers themselves


# A simple function to clean up empty chars at the beginning of each line of a var
def remove_leading_spaces(text):
    # split the text into lines, remove leading spaces from each line, and rejoin them
    cleaned_text = "\n".join([line.lstrip() for line in text.split("\n")])
    return cleaned_text


def run_splunk_search(service, search_query, search_params, max_retries, sleep_time):
    """
    Executes a Splunk search with a retry mechanism.

    :param search_query: The Splunk search query to execute.
    :param search_params: Parameters for the search query.
    :param max_retries: Maximum number of retries for the search.
    :param sleep_time: Time to wait between retries in seconds.
    :return: A reader object with the search results.
    """
    current_retries = 0
    while current_retries < max_retries:
        try:
            search_results = service.jobs.export(search_query, **search_params)
            return results.JSONResultsReader(search_results)
        except Exception as e:
            if "maximum number of concurrent historical searches" in str(e):
                current_retries += 1
                logging.warn(
                    f'temporary search failure, retry {current_retries}/{max_retries} for Splunk search due to error="{str(e)}", will re-attempt in {sleep_time} seconds.'
                )
                time.sleep(sleep_time)
            else:
                logging.error(
                    f'permanent search failure, search failed with exception="{str(e)}", search_query="{search_query}", search_params="{search_params}"'
                )
                raise

    raise Exception(
        f'permanent search failure after reaching max retries, attempt="{current_retries}", max_retries="{max_retries}", search_query="{search_query}", search_params="{search_params}"'
    )
