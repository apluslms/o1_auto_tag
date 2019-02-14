#!/usr/bin/env python3
import socket
import logging
import json
import datetime
import queue
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
 check that site url (key 'site') resolves to ip of REMOTE_ADDR - https://github.com/Aalto-LeTech/a-plus/blob/master/lib/helpers.py#L113
'''

conf_file = "conf.json"

with open(conf_file, "r") as f:
    CONF = json.load(f)

p = ArgumentParser()
p.add_argument('-v', '--verbose', action='count',
               help="Print logger.messages")
p.add_argument('-s', '--server', action='store_true', 
               help="Run the server")
p.add_argument('-b', '--batch',
               help="Run a batch job, go through tags from last N hours", type=int)
args = p.parse_args()

this_logger_name = "TagLogger"
logging.basicConfig()
logger = logging.getLogger(this_logger_name) 
#print(args.verbose)
logger.setLevel(level=logging.WARNING if args.verbose < 1  else
                      logging.INFO    if args.verbose == 1 else 
                      logging.DEBUG   if args.verbose == 2 else 
                      logging.DEBUG)

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
    
    logger.info("")
    logger.info("submission_id: {id}".format(id=submission_id))
    submission = get_submission(submission_id)
    submitters = submission['submitters']
    submission_data = submission.get_item('submission_data')
    
    logger.info("submission_data:")
    logger.info(pformat(submission_data))

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
        logger.info("")
        logger.info("With {code}".format(code=r.status_code))
        if r.status_code is not '201':
            logger.info(r.json())
            logger.info("")


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
        #logger.info("Putting into queue...") 
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
    @cached(TTLCache(100, ttl=30))
    def get_url_ip_address_list(self, url):
        """
        This function takes a full URL as a parameter and returns the IP addresses
        of the host as a string.
        It will cache results for 30 seconds, so repeated calls return fast
        """
        hostname = urlsplit(url).hostname
        assert hostname, "Invalid url: no hostname found"
        ips = (a[4][0] for a in socket.getaddrinfo(hostname, None, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP))
        return tuple(set(ips))
    
    def do_POST(self):
        parameters = parse_qs(urlsplit(self.path).query)
        content_length = int(self.headers['Content-Length'])
        post_data = parse_qs(self.rfile.read(content_length).decode('utf-8'))
        token = (post_data.get('token') or parameters.get('token') or (None,))[0]
        logger.info("With token {token}".format(token=token))
        hook_token = CONF.get('hook_token')
        if hook_token and (not token or token != hook_token):
            logger.warning('Hook token doesn\'t match or was missing in POST')
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Bad auth token: missing or invalid')
            return
        reported_site = post_data.get('site')[0]
        supposed_ips = self.get_url_ip_address_list(reported_site)
        client_ip = self.client_address[0]  # What about port?
        if client_ip not in supposed_ips[0]: 
            logger.warning('Client ip doesn\'t match reported in POST body')
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Deceptive: sender ip does not match POST parameter') # Should this hint be given?
            return

        exercise_id, *_ = (int(id) for id in post_data['exercise_id'])
        submission_id, *_ = (int(id) for id in post_data['submission_id'])
        # Wait before making requests to A+, because the submission is not ready
        # to be read from the API when A+ calls the hook
        self.server.call_queue.schedule(add_tagging, exercise_id, submission_id)
        self.send_response(204)
        self.end_headers()
        self.wfile.write(b'OK')


def run_server(server_class=QueuingHTTPServer,
        handler_class=APlusCourseHookHTTPRequestHandler):
    httpd = server_class(tuple(CONF['server_address']), handler_class)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Gracefully shutting down server...") # TODO: how many workers left
        httpd.server_close()


def do_batch(hours_since):
    for exercise_id in CONF['exercise_ids']:
        submissions = get_submissions_list(exercise_id)
        for submission in submissions:
            age_hours = how_recent_in_hours(submission['submission_time'])
            logger.info("")
            logger.info("Submission with ID {id} is {hours} hours old".format(id=submission['id'], hours=age_hours))
            if age_hours < hours_since:
                logger.info("-> try to add tags")
                add_tagging(exercise_id, submission['id'])
            else:
                logger.info("-> don't try to add tags")
                logger.info("stopping\n")
                break


if __name__ == '__main__':
    if args.batch:
        logger.info('\n'*2)
        logger.info("Running batch")
        do_batch(args.batch) 
    if args.server:
        logger.info("Running server")
        run_server()
