#!/usr/bin/env python3
import logging
from aplus_client.client import AplusTokenClient
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from itertools import chain
from threading import Timer
from urllib.parse import parse_qs

CONFIG = {
    'base_url': 'http://localhost:8000/api/v2/',
    'courses_url': '/courses/',
    'exercises_url': '/exercises/',
    'submissions_url': '/submissions/',
    'taggings_url': '/taggings/',
    'taggings_query': '?tag_id=',
    'course_id': 3,
    'exercise_ids': {2262, 2263},
    'server_address': ('', 8888),
    'wait_after_post': 5,
}

tag_for_form_value = {
    'kielitaito': {
        'suomi': 'fi',
        'ruotsi': 'sv',
        'englanti': 'en',
    },
}

p = ArgumentParser()
p.add_argument('-v', '--verbose', action='store_true',
               help="Print logging messages")
p.add_argument('-t', '--token', help='Token for A+ API')
args = p.parse_args()

if args.verbose:
    logging.basicConfig(level=logging.DEBUG)

api = AplusTokenClient(args.token)
api.set_base_url_from(CONFIG['base_url'])

def get_submission(submission_id):
    return api.load_data('{submissions_url}{submission_id}/'
                         .format(**CONFIG, submission_id=submission_id))

def add_tagging(exercise_id, submission_id):
    if exercise_id not in CONFIG['exercise_ids']:
        return

    submission = get_submission(submission_id)
    submitters = submission['submitters']
    submission_data = submission['submission_data']

    tag_slugs = (tag_for_form_value[field[0]][field[1]]
                 for field in submission_data
                 if field[0] in tag_for_form_value)
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
        api.do_post('{courses_url}{course_id}{taggings_url}'
                    .format(**CONFIG), json=data)

class APlusCourseHookHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = parse_qs(self.rfile.read(content_length).decode('utf-8'))
        exercise_id, *_ = (int(id) for id in post_data['exercise_id'])
        submission_id, *_ = (int(id) for id in post_data['submission_id'])
        # Wait before making requests to A+, because the submission is not ready
        # to be read from the API when A+ calls the hook
        Timer(CONFIG['wait_after_post'],
              add_tagging,
              (exercise_id, submission_id)).start()
        self.send_response(204)

def run(server_class=HTTPServer,
        handler_class=APlusCourseHookHTTPRequestHandler):
    httpd = server_class(CONFIG['server_address'], handler_class)
    httpd.serve_forever()
    httpd.server_close()

if __name__ == '__main__':
    run()
