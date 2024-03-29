#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__version__ = "0.1.0"
__status__ = "PRODUCTION"

import os
import sys
import splunk
import splunk.entity
import json
import logging
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = logging.FileHandler(
    splunkhome + "/var/log/splunk/checkmloutliers.log", "a"
)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s"
)
logging.Formatter.converter = time.gmtime
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr, logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)  # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-check-mloutlier", "lib"))

# import mloutliers libs
from mloutliers_libs import run_splunk_search, remove_leading_spaces

# import Splunk libs
from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)
from splunklib import six
import splunklib.client as client


@Configuration()
class CheckMLOutliers(StreamingCommand):

    kpi_name = Option(
        doc="""
        **Syntax:** **kpi_name=****
        **Description:** Name of the KPi to be inspected.""",
        require=False,
        default="None",
        validate=validators.Match("kpi_name", r"^.*$"),
    )

    entity_field = Option(
        doc="""
        **Syntax:** **entity_field=****
        **Description:** Name of the fields containing the entity value.""",
        require=False,
        default="None",
        validate=validators.Match("entity_field", r"^.*$"),
    )

    metric_index = Option(
        doc="""
        **Syntax:** **metric_index=****
        **Description:** Name of metric index to query.""",
        require=False,
        default="None",
        validate=validators.Match("metric_index", r"^.*$"),
    )

    span = Option(
        doc="""
        **Syntax:** **span=****
        **Description:** Time bucket span definition.""",
        require=False,
        default="span=10m",
        validate=validators.Match("span", r"^.*$"),
    )

    time_factor = Option(
        doc="""
        **Syntax:** **	time_factor=****
        **Description:** Name of the field containing the time factor definition.""",
        require=False,
        default="time_factor",
        validate=validators.Match("time_factor", r"^.*$"),
    )

    outliers_earliest = Option(
        doc="""
        **Syntax:** **	outliers_earliest=****
        **Description:** Name of the field containing the outliers_earliest definition.""",
        require=False,
        default="outliers_earliest",
        validate=validators.Match("outliers_earliest", r"^.*$"),
    )

    # status will be statically defined as imported

    def stream(self, records):

        # set loglevel
        loglevel = "INFO"
        conf_file = "ta_check_mloutlier_settings"
        confs = self.service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == "logging":
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        logginglevel = logging.getLevelName(loglevel)
        log.setLevel(logginglevel)

        # Loop in the results
        for record in records:

            # get the entity_name
            entity_name = record[self.entity_field]

            # get the KPI current value
            current_value = record[self.kpi_name]

            # get the time_factor
            try:
                time_factor = record[self.time_factor]
                # ensure time_factor in between double quotes, if not add them
                if not time_factor.startswith('"') and not time_factor.endswith('"'):
                    time_factor = f'"{time_factor}"'
                # define the full statement
                time_factor = f"strftime(_time, {time_factor})"

            except:
                time_factor = None

            # accept none as the time factor
            if time_factor == "none":
                time_factor = None

            # get outliers_earliest
            try:
                outliers_earliest = record[self.outliers_earliest]
            except:
                outliers_earliest = "-30d"

            # get span
            try:
                span = record[self.span]
            except:
                span = "span=10m"

            # build the Splunk query
            search_query = f'| mstats avg({self.kpi_name}) as {self.kpi_name} where index="{self.metric_index}" entity="{entity_name}" by entity {span}'

            if time_factor:
                search_query += f"""\n| eval factor={time_factor}"""
                search_query += f"""\n| fit DensityFunction {self.kpi_name} lower_threshold=0.005 upper_threshold=0.005 by factor"""
            else:
                search_query += f"""\n| fit DensityFunction {self.kpi_name} lower_threshold=0.005 upper_threshold=0.005"""

            search_query = remove_leading_spaces(
                f"""\
                {search_query}
                | rex field=BoundaryRanges "(-Infinity:(?<LowerBound>[\d|\.]*))|((?<UpperBound>[\d|\.]*):Infinity)"
                | foreach LowerBound UpperBound [ eval <<FIELD>> = if(isnum('<<FIELD>>'), '<<FIELD>>', 0) ]
                | fields _time {self.kpi_name} LowerBound UpperBound
                | sort - 0 _time
                | head 1
                | eval isLowerOutlier = if({self.kpi_name} < LowerBound, 1, 0), isUpperOutlier = if({self.kpi_name} > UpperBound, 1, 0)
            """
            )

            # kwargs
            search_kwargs = {
                "earliest_time": outliers_earliest,
                "latest_time": "now",
                "output_mode": "json",
                "count": 0,
            }

            # init a yield record
            yield_record = {
                "kpi_name": self.kpi_name,
                "current_value": current_value,
                "search_query": search_query,
                "search_kwargs": search_kwargs,
            }

            # Attemp to execute the search
            search_start = time.time()
            try:
                search_start = time.time()
                reader = run_splunk_search(
                    self.service,
                    search_query,
                    search_kwargs,
                    24,
                    5,
                )

                for item in reader:
                    if isinstance(item, dict):
                        logging.info(
                            f'Check ML Outliers, Processing results from ML check search, result="{json.dumps(item, indent=2)}"'
                        )
                        lowerBound_value = item["LowerBound"]
                        upperBound_value = item["UpperBound"]
                        isLowerOutlier = item["isLowerOutlier"]
                        isUpperOutlier = item["isUpperOutlier"]
                        yield_record["lowerBound"] = lowerBound_value
                        yield_record["upperBound"] = upperBound_value
                        yield_record["isLowerOutlier"] = isLowerOutlier
                        yield_record["isUpperOutlier"] = isUpperOutlier

                # log and add to yield record
                ml_message = f"ML investigations results, entity={entity_name}, kpi={self.kpi_name}, current_value={current_value}, lowerBound={lowerBound_value}, upperBound={upperBound_value}, isLowerOutlier={isLowerOutlier}, isUpperOutlier={isUpperOutlier}, run_time={round(time.time() - search_start, 3)}"
                logging.info(ml_message)
                yield_record["ml_message"] = ml_message

            except Exception as e:
                logging.error(f"Failed to execute Splunk search with error: {str(e)}")
                msg = f'Check ML Outliers, failed to process search, exception="{str(e)}", run_time="{time.time() - search_start}"'
                logging.error(msg)
                yield_record["error"] = msg

            # loop trough existing key value pairs in record and add to yield_record
            for key, value in record.items():
                yield_record[key] = value

            yield yield_record


dispatch(CheckMLOutliers, sys.argv, sys.stdin, sys.stdout, __name__)
