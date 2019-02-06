#!/usr/bin/env python3
import logging
import json
import datetime
from aplus_client.client import AplusTokenClient, AplusApiList, AplusApiDict
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from itertools import chain
from threading import Timer
from urllib.parse import parse_qs, urlsplit
from pprint import pprint



#TODO:
'''
 Change printing to logging

 Server mode and batch mode, in batch mode go through all of the 
 submissions to the exercise/exercises (from the last day?) and set tags  

 POST pool, so 1 request every N ms

 validate token from query string `/?token=foobar` or body (aplus addition: parameters to POST body)
 
 check that site url resolves to ip of REMOTE_ADDR - https://github.com/Aalto-LeTech/a-plus/blob/master/lib/helpers.py#L113
'''

conf_file = "conf.json"

with open(conf_file, "r") as f:
    CONF = json.load(f)

p = ArgumentParser()
p.add_argument('-v', '--verbose', action='store_true',
               help="Print logging messages")
p.add_argument('-s', '--server', action='store_true', 
               help="Run the server")
p.add_argument('-b', '--batch',
               help="Run a batch job, go through tags from last N hours", type=int)
args = p.parse_args()

if args.verbose:
    logging.basicConfig(level=logging.DEBUG)

api = AplusTokenClient(CONF['api_token'])
api.set_base_url_from(CONF['base_url'])

def get_submission(submission_id):
    return api.load_data('{submissions_url}{submission_id}'
                         .format(**CONF, submission_id=submission_id))

def get_submissions_list(exercise_id):
    return api.load_data('{exercises_url}{exercise_id}{submissions_url}'
                         .format(**CONF, exercise_id=exercise_id))

def how_recent_in_hours(ISO8601_datetime_string):
    # Times in UTC
    datetime_other = datetime.datetime.strptime(ISO8601_datetime_string, "%Y-%m-%dT%H:%M:%S.%fZ")
    datetime_now   = datetime.datetime.utcnow()
    time_delta = datetime_now - datetime_other
    time_delta_hours = time_delta.total_seconds() / 3600
    return round(time_delta_hours, 1)

def add_tagging(exercise_id, submission_id):
    if exercise_id not in CONF['exercise_ids']:
        return
    
    print()
    print("submission_id:", submission_id)
    submission = get_submission(submission_id)
    #print("submission:") 
    #pprint(submission._data)
    submitters = submission['submitters']
    submission_data = submission.get_item('submission_data')
    
    #pprint(submitters)
    print("submission_data:")
    pprint(submission_data)

    tag_slugs = (CONF['tag_for_form_value'][field[0]][field[1]]
                 for field in submission_data
                 if field[0] in CONF['tag_for_form_value'])
    user_ids = (submitter['id'] for submitter in submitters)
    post_dataset = (
        {
            'user': {
                'id': user_id,
            },
            'tag': {
                'slug': tag_slug,
            },
        }
        for user_id in user_ids
        for tag_slug in tag_slugs)

    for data in post_dataset:
        # r is a Requests Response object
        r = api.do_post('{courses_url}{course_id}{taggings_url}'
                        .format(**CONF), json=data)
        print()
        print("With", r.status_code)
        if r.status_code is not '201':
            print(r.json())
            print()

class APlusCourseHookHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        parameters = parse_qs(urlsplit(self.path).query)
        content_length = int(self.headers['Content-Length'])
        post_data = parse_qs(self.rfile.read(content_length).decode('utf-8'))
        token = parameters.get('token', post_data.get('token', (None,)))[0]
        print(token)
        #pprint(post_data)
        exercise_id, *_ = (int(id) for id in post_data['exercise_id'])
        submission_id, *_ = (int(id) for id in post_data['submission_id'])
        # Wait before making requests to A+, because the submission is not ready
        # to be read from the API when A+ calls the hook
        Timer(CONF['wait_after_post'],
              add_tagging,
              (exercise_id, submission_id)).start()
        self.send_response(204)

def run_server(server_class=HTTPServer,
        handler_class=APlusCourseHookHTTPRequestHandler):
    httpd = server_class(tuple(CONF['server_address']), handler_class)
    httpd.serve_forever()
    httpd.server_close()

def do_batch(hours_since=24):
    for exercise_id in CONF['exercise_ids']:
        submissions = get_submissions_list(exercise_id)
        for submission in submissions:
            age_hours = how_recent_in_hours(submission['submission_time'])
            print()
            print("Submission id", submission['id'], "is", age_hours, "hours old")
            if age_hours < hours_since:
                print("-> try to add tags")
                add_tagging(exercise_id, submission['id'])
            else:
                print("-> don't try to add tags")
                print("stopping\n")
                break

if __name__ == '__main__':
    print('\n'*2)
    if args.batch:
        logging.info("Running batch")
        do_batch(args.batch) 
    if args.server:
        logging.info("Running server")
        run_server()
