#!/usr/bin/env python

from datetime import datetime
import json
import logging
import os
import sys
import subprocess
import time

logging.basicConfig(filename='devfactory-travis.log', level=logging.DEBUG)
PLUGIN_NAME = "Devfactory Dependency Analyser"
LOGGER_NAME = 'DEVFACTORY_LOGGER'

logger = logging.getLogger(LOGGER_NAME)
output_handler = logging.StreamHandler(sys.stdout)
output_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
output_handler.setFormatter(formatter)
logger.addHandler(output_handler)

if sys.version[0] == '3':
    logger.error("Python 3 is not supported by this plugin")
    sys.exit(0)

import urllib2

install_command = os.environ.get('DF_INSTALL_COMMAND')
DEFAULT_INSTALL_COMMAND = 'mvn install -DskipTests'
BASE_URL = "http://aline-cnu-apielast-1qrfta1b7d7r3-412496036.us-east-1.elb.amazonaws.com"

POST_API_URL = BASE_URL + '/api/jobs'
POLL_API_URL = BASE_URL + '/api/jobs/%d/summary'  # Add job_id parameter
SUCCESS_MESSAGE = 'success'
TIMEOUT = 1200  # Timeout is 20 minutes. Change as per requirement
POST_REQUEST_RETRY_TIMEOUT = 10  # Wait 30 seconds if post request fails
START_POLLING_TIMEOUT = 20  # Wait 30 seconds before starting polling for results
RESULT_POLL_TIMEOUT = 10  # Wait 30 seconds between api polling for results

def _get_dependency_list():
    list_command = "mvn dependency:list -DincludeScope=runtime > df_list_output.txt"
    command = "cat df_list_output.txt | sed -ne s/..........// -e /patterntoexclude/d -e s/:compile//p -e s/:runtime//p | sort | uniq"
    # Getting list of dependencies using Maven
    subprocess.check_output(list_command, shell=True)
    output = subprocess.check_output(command, shell=True)
    dependency_list = output.split("\n")
    dependencies = [':'.join(dependency.split(':')[:2] + [dependency.split(':')[-1]]) for dependency in dependency_list if dependency]
    return dependencies

def _get_dependencies():
    try:
        return _get_dependency_list()
    except:
        try:
            logger.warn("Dependency list command failed to execute, Trying to install and rerun")
            if install_command:
                logger.info("Running user provided custom installation command")
                subprocess.check_output(install_command, shell=True)
            else:
                subprocess.check_output(DEFAULT_INSTALL_COMMAND, shell=True)
                logger.info("Running default installation command")
            logger.info("Trying to extract dependencies using dependency list after install")
            return _get_dependency_list()
        except:
            return None

def _get_post_data(dependencies):
    # Create data for POST request
    modules = [
                dict(
                    name=None,
                    lib_path=None,
                    source_path=None,
                    bin_path=None,
                    gav_list=dependencies
                )
            ]
    post_data = {}
    post_data['modules'] = modules
    post_data['ci_system'] = "TRAVIS-PLUGIN"
    post_data['protocol'] = "LIST"
    post_data['product_version_id'] = os.environ.get("TRAVIS_JOB_ID")
    post_data['build_id'] = os.environ.get("TRAVIS_BUILD_ID")
    post_data['product_id'] = os.environ.get("TRAVIS_REPO_SLUG")
    post_data['scm_type'] = 'git'
    return post_data

def _send_post_request(post_data):
    retry_count = 0
    job = None
    logger.info("Post data is : ")
    logger.info(post_data)
    while retry_count < 3:
        retry_count += 1
        try:
            request = urllib2.Request(POST_API_URL)
            request.add_header('Content-Type', 'application/json')
            response = urllib2.urlopen(request, json.dumps(post_data))
            config = json.load(response)
            logger.info("return data is: ")
            logger.info(config)
            if 'status' in config and config['status'].lower() == SUCCESS_MESSAGE:
                return config['data']
        except:
            logger.info("Could not complete job creation post request. Retrying!!")
            time.sleep(POST_REQUEST_RETRY_TIMEOUT)
    if retry_count >= 3 or job is None:
        logger.warn("%s : Failed to send dependencies to server! Exiting Analysis" % PLUGIN_NAME)
    logger.info(job)
    return job

def _poll_for_results(job):
    try:
        request = urllib2.Request(POLL_API_URL % job['id'])
        response = urllib2.urlopen(request)
        config = json.load(response)
        if 'status' in config and config['status'].lower() == SUCCESS_MESSAGE:
            return config['data']
        else:
            return None
    except:
        return None

def _print_results(results):
    logger.info("=====================================")
    logger.warn("Found Libraries with Security Vulnerabilities!")
    logger.warn("%d Libraries with High Security Vulnerabilities" % results['security_high'])
    logger.warn("%d Libraries with Medium Security Vulnerabilities" % results['security_medium'])
    logger.info("=====================================")


def process():
    try:
        start_time = datetime.now()
        dependencies = _get_dependencies()
        if dependencies:
            post_data = _get_post_data(dependencies)
            logger.info("Successfully found dependencies for Analysis. Sending dependencies to server for processing")
            # Send POST request
            job = _send_post_request(post_data)
            if job is None:
                logger.info("Failed to create job !")
                return True
            logger.info("Job id for newly created job is: %d" % job['id'])
            # Wait and Poll API for results. Exit if time is up
            logger.info("%s : Waiting for results from server" % PLUGIN_NAME)
            time.sleep(START_POLLING_TIMEOUT)
            count = 0
            while True:
                count += 1
                logger.info("Polling DB results: Attempt %d" % count)
                if (datetime.now() - start_time).seconds > TIMEOUT:
                    logger.warn("%s : Timeout reached! Failed to get results. Exiting Analysis" % PLUGIN_NAME)
                    return True
                results = _poll_for_results(job)
                if results:
                    logger.info("Results received from server: ")
                    logger.info(results)
                    if results['vulnerable_libraries'] > 0:
                        _print_results(results)
                        return False
                    else:
                        logger.info("Received results from server. No Vulnerabilities found")
                        return True
                time.sleep(RESULT_POLL_TIMEOUT)
            return True
        else:
            logger.info("Failed to get list of dependencies for the project")
    except subprocess.CalledProcessError:
        logger.exception("Error in subprocess")
        return True
    except:
        logger.exception("Unknown Error in DF Analyser")
        return True

if __name__ == '__main__':
    logger.info("============================")
    logger.info("%s : Starting Analysis " % PLUGIN_NAME)
    if process():
        logger.info("%s : Exiting" % PLUGIN_NAME)
        logger.info("============================")
        sys.exit(0)
    else:
        logger.info("%s: Analysis Completed Vulnerable dependencies found! Please fix these libraries" % PLUGIN_NAME)
        logger.info("============================")
        sys.exit(1)
