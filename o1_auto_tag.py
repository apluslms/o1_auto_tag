#!/usr/bin/env python3
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
Create tag when one doesn't yet exist

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
logger.setLevel(level=logging.WARNING if args.verbose == None else
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

@cached(TTLCache(100, ttl=30))
def get_url_ip_address_list(hostname):
    ips = (a[4][0] for a in socket.getaddrinfo(hostname, None, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP))
    return tuple(set(ips))

def send_response(self, code, headers=None, msg=""):
    self.send_response(code)
    if headers:
        self.end_headers(headers)
    else:
        self.end_headers()
    self.wfile.write(b'Deceptive: sender ip does not match POST parameter') # Should this hint be given?


def add_tagging(exercise_id, submission_id):
    if exercise_id not in CONF['exercise_ids']:
        return
    logger.info("Getting submission with id %s", submission_id)
    submission = get_submission(submission_id)
    if not submission:
        logger.warning("Submission fetch failed. API token is likely invalid.")
        return
    submitters = submission['submitters']
    submission_data = submission.get_item('submission_data')
    logger.info("submission data: \n%s", pformat(submission_data))
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
        logger.debug("")
        logger.debug("With {code}".format(code=r.status_code))
        if r.status_code == requests.codes.created: # 201
            logger.info("Added tagging %s to user %s", data['tag'], data['user'])
        else:
            logger.debug(r.json())
            logger.debug("")


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
        logger.info("HOOK with token {token}".format(token=token))
        hook_token = CONF.get('hook_token')
        if hook_token and (not token or token != hook_token):
            logger.debug('Hook token doesn\'t match or was missing in POST')
            send_response(self, 401, msg=b'Bad auth token: missing or invalid')
            return
        reported_site_parsed = urlsplit(post_data.get('site')[0])
        base_url_netloc = urlsplit(CONF['base_url']).netloc 
        reported_netloc = reported_site_parsed.netloc
        if base_url_netloc != reported_netloc: # and False:
            logger.debug('base_url netloc in config %s doesn\'t match POST parameter \'site\' %s netloc', 
                         base_url_netloc,
                         reported_netloc)
            send_response(self, 400, msg="Base url given in parameter 'site' does not match config")
            return
        supposed_ips = get_url_ip_address_list(reported_site_parsed.hostname)
        client_ip = self.client_address[0]
        if client_ip not in supposed_ips: 
            logger.debug('Client ip %s doesn\'t match reported ips %s in POST body', client_ip, supposed_ips)
            send_response(self, 400, msg="Deceptive: client does not match POST parameter 'site' after resolve")
            return

        exercise_id, *_ = (int(id) for id in post_data['exercise_id'])
        submission_id, *_ = (int(id) for id in post_data['submission_id'])
        self.server.call_queue.schedule(add_tagging, exercise_id, submission_id)
        send_response(self, 204, msg="OK")


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
    did = ""
    if args.batch:
        logger.info('\n'*2)
        logger.info("Running batch")
        do_batch(args.batch)
        did += "b"
    if args.server:
        logger.info("Running server")
        run_server()
        did += "s"
    if did == "":
        logger.warning("No flags given")

