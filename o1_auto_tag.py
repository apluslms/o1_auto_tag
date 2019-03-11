#!/usr/bin/env python3
import time
import socket
import logging
import json
import datetime
import queue
import requests
from aplus_client.client import AplusTokenClient, AplusApiList, AplusApiDict
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from itertools import chain
from threading import Timer, Event
from urllib.parse import parse_qs, urlsplit
from pprint import pprint, pformat
from queue_worker import Worker
from cachetools import cached, TTLCache


#TODO:
''' 
README.md
'''

conf_file = "conf.json"

with open(conf_file, "r") as f:
    CONF = json.load(f)

p = ArgumentParser()
p.add_argument('-v', '--verbose', action='count',
               help="Print more information, stackable")
p.add_argument('-s', '--server', action='store_true', 
               help="Run the server")
p.add_argument('-b', '--batch',
               help="Run a batch job, go through tags from last N hours", type=int)
args = p.parse_args()

this_logger_name = "TagLogger"
logging.basicConfig()
logger = logging.getLogger(this_logger_name) 
logger.setLevel(level=logging.WARNING if args.verbose == None else
                      logging.INFO    if args.verbose == 1 else 
                      logging.DEBUG   if args.verbose == 2 else 
                      logging.DEBUG)

api = AplusTokenClient(CONF['api_token'])
api.set_base_url_from(CONF['base_url'])

sess = requests.Session()


def get_submission(submission_id):
    return api.load_data('{submissions_url}{submission_id}'
                         .format(**CONF, submission_id=submission_id))

def get_submissions_list(exercise_id):
    return api.load_data('{exercises_url}{exercise_id}{submissions_url}'
                         .format(**CONF, exercise_id=exercise_id))

def get_usertags():
    return api.load_data('{courses_url}{course_id}{usertags_url}'
                         .format(**CONF))

def post_tagging(data):
    return api.do_post('{courses_url}{course_id}{taggings_url}'
                        .format(**CONF), json=data)

def post_usertag(**data):
    return api.do_post('{courses_url}{course_id}{usertags_url}'
                       .format(**CONF), json=data)    

def default_tag(name, slug):
    return { 
               "name":                name,
               "slug":                slug,
               "description":         'Auto added by o1_auto_tag.py',
               "color":               '#000000',
               "visible_to_students": False
           }

def how_recent_in_hours(ISO8601_datetime_string):
    # Times in UTC
    datetime_other = datetime.datetime.strptime(ISO8601_datetime_string, "%Y-%m-%dT%H:%M:%S.%fZ")
    datetime_now   = datetime.datetime.utcnow()
    time_delta = datetime_now - datetime_other
    time_delta_hours = time_delta.total_seconds() / 3600
    return round(time_delta_hours, 1)

@cached(TTLCache(100, ttl=30))
def get_url_ip_address_list(hostname):
    ips = (a[4][0] for a in socket.getaddrinfo(hostname, None, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP))
    return tuple(set(ips))

def send_response(Handler, code, headers=None, msg=""):
    Handler.send_response(code)
    if headers:
        Handler.end_headers(headers)
    else:
        Handler.end_headers()
    Handler.wfile.write(msg)


def submission_to_tag_post(submission): 
    submitters = submission['submitters']
    submission_data = submission.get_item('submission_data')
    logger.debug("submission data: \n%s", pformat(submission_data))
    tag_slugs = (CONF['tag_for_form_value'][field[0]][field[1]]
                 for field in submission_data
                 if    field[0] in CONF['tag_for_form_value']
                   and field[1] in CONF['tag_for_form_value'][field[0]])
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
    return post_dataset


def add_tagging(exercise_id, submission_id):
    if exercise_id not in CONF['exercise_ids']:
        return
    logger.info("Submission with id %s", submission_id)
    submission = get_submission(submission_id)
    if not submission:
        logger.warning("Submission fetch failed. API token is likely invalid.")
        return

    post_dataset = submission_to_tag_post(submission)

    for data in post_dataset:
        slug = data['tag']['slug']
        # r is a Requests Response object
        r_tagging = post_tagging(data)
        logger.debug("Response with %s", r_tagging.status_code)
        if r_tagging.status_code == requests.codes.created: # 201
            logger.info("Added tagging %s to user %s", data['tag'], data['user'])
        else:
            logger.debug("%s\n ", r_tagging.json())


class IntervalCallQueue():
    def __init__(self, interval_s):
        self._queue = queue.Queue()
        self.stop_marker = "!stop"
        def call_next():
            if not self.queue.empty():
                f, args = self.queue.get_nowait()
                f(*args)
        self._workers = [Worker(self._queue, self.stop_marker, interval_s) for _ in range(CONF["worker_count"])]
    
    def schedule(self, f, *args):
        self._queue.put((f, args))

    def stop(self):
        for _ in self._workers:
            self._queue.put(self.stop_marker)
        for i, worker in enumerate(self._workers):
            worker.join()
            logger.info("Worker #{number} stopped".format(number=i+1))

    
class QueuingHTTPServer(HTTPServer):
    def __init__(self, *args, **kwargs):
        self.call_queue = IntervalCallQueue(CONF["worker_interval"])
        super().__init__(*args, **kwargs)
    
    def server_close(self):
        self.call_queue.stop()
        super().server_close()


class APlusCourseHookHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        parameters = parse_qs(urlsplit(self.path).query)
        content_length = int(self.headers['Content-Length'])
        post_data = parse_qs(self.rfile.read(content_length).decode('utf-8'))
        token = (post_data.get('token') or parameters.get('token') or (None,))[0]
        logger.info("HOOK with token %s", token)
        hook_token = CONF.get('hook_token')
        if hook_token and (not token or token != hook_token):
            logger.debug('Hook token doesn\'t match or was missing in POST')
            send_response(self, 401, msg=b'Bad auth token: missing or invalid')
            return
        reported_site_parsed = urlsplit(post_data.get('site')[0])
        base_url_netloc = urlsplit(CONF['base_url']).netloc 
        reported_netloc = reported_site_parsed.netloc
        if base_url_netloc != reported_netloc:
            logger.debug('base_url netloc in config %s doesn\'t match POST parameter \'site\' %s netloc', 
                         base_url_netloc, reported_netloc)
            send_response(self, 400, msg=b"Base url given in parameter 'site' does not match config")
            return
        supposed_ips = get_url_ip_address_list(reported_site_parsed.hostname)
        client_ip = self.client_address[0]
        if client_ip not in supposed_ips: 
            logger.debug('Client ip %s doesn\'t match reported ips %s in POST body', client_ip, supposed_ips)
            send_response(self, 400, msg=b"Deceptive: client does not match POST parameter 'site' after resolve")
            return

        exercise_id, *_ = (int(id) for id in post_data['exercise_id'])
        submission_id, *_ = (int(id) for id in post_data['submission_id'])
        self.server.call_queue.schedule(add_tagging, exercise_id, submission_id)
        send_response(self, 204, msg="OK")


def sync_tags():
    usertags = get_usertags()
    existing_slugs = [tag['slug'] for tag in usertags]
    for field_name, value_to_slug in CONF['tag_for_form_value'].items():
        missing_mappings = filter(lambda x: x[1] not in existing_slugs, value_to_slug.items())
        for value, slug in missing_mappings:
            tag_name = field_name + value.capitalize()
            r_usertag = post_usertag(**default_tag(name=tag_name, slug=slug))
            if r_usertag.status_code == requests.codes.created:
                logger.info("Added tag with slug %s", slug)
            else:
                logger.info("Adding usertag failed")
                logger.debug("Usertag data:\n%s", r_usertag.request.body)


def run_server(server_class=QueuingHTTPServer,
               handler_class=APlusCourseHookHTTPRequestHandler):
    httpd = server_class(tuple(CONF['server_address']), handler_class)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Gracefully shutting down server...")
        httpd.server_close()


def do_batch(hours_since):
    for exercise_id in CONF['exercise_ids']:
        logger.info("Exercise with ID %s\n", exercise_id)
        submissions = get_submissions_list(exercise_id)
        added_count = 0
        for submission in submissions:
            age_hours = how_recent_in_hours(submission['submission_time'])
            logger.debug("Submission with ID %s is %s hours old", submission['id'], age_hours)
            if age_hours < hours_since:
                logger.debug("-> add taggings")
                add_tagging(exercise_id, submission['id'])
                added_count += 1
            else:
                logger.debug("-> don't add taggings")
                logger.debug("stopping")
                break
        logger.info("    -- Added taggings from %s/%s submissions\n\n", added_count, len(submissions))



if __name__ == '__main__':
    did = ""
    sync_tags()
    if args.batch:
        logger.info("Running batch")
        do_batch(args.batch)
        did += "b"
    if args.server:
        logger.info("Running server")
        run_server()
        did += "s"
    if did == "":
        logger.warning("No flags given")

