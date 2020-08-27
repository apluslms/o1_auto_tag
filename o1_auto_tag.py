#!/usr/bin/env python3
import datetime
import json
import logging
import os
import queue
import requests
import socket
import time
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import UnixStreamServer, TCPServer
from itertools import chain
from pprint import pprint, pformat
from queue_worker import Worker
from threading import Timer, Event
from urllib.parse import parse_qs, urlsplit

from aplus_client.client import AplusTokenClient, AplusApiList, AplusApiDict
from cachetools import cached, TTLCache


this_logger_name = "TagLogger"
logger = logging.getLogger(this_logger_name)


def get_submission(submission_id):
    return api.load_data('{submissions_url}{submission_id}'
                         .format(submission_id=submission_id, **CONF))

def get_submissions_list(exercise_id):
    return api.load_data('{exercises_url}{exercise_id}{submissions_url}'
                         .format(exercise_id=exercise_id, **CONF))

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
    if ISO8601_datetime_string[-6] in '+-' and ISO8601_datetime_string[-3] == ':':
        # converts +03:00 to +0300
        ISO8601_datetime_string = ISO8601_datetime_string[:-3] + ISO8601_datetime_string[-2:]
    if ISO8601_datetime_string[-1] == 'Z':
        datetime_other = datetime.datetime.strptime(ISO8601_datetime_string, "%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        datetime_other = datetime.datetime.strptime(ISO8601_datetime_string, "%Y-%m-%dT%H:%M:%S.%f%z")
        datetime_other = datetime_other.astimezone(datetime.timezone.utc)
        datetime_other = datetime_other.replace(tzinfo=None)
    datetime_now = datetime.datetime.utcnow()
    time_delta = datetime_now - datetime_other
    time_delta_hours = time_delta.total_seconds() / 3600
    return round(time_delta_hours, 1)

@cached(TTLCache(100, ttl=30))
def get_url_ip_address_list(hostname):
    try:
        ips = (a[4][0] for a in socket.getaddrinfo(hostname, None, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP))
    except socket.gaierror:
        logger.debug("Not address found for %r", hostname)
        ips = ()
    return tuple(set(ips))

def send_response(Handler, code, headers=None, msg=""):
    Handler.send_response(code)
    if headers:
        Handler.end_headers(headers)
    else:
        Handler.end_headers()
    if isinstance(msg, str):
        msg = msg.encode('utf-8')
    Handler.wfile.write(msg)


def submission_to_tag_post(submission): 
    submitters = submission['submitters']
    submission_data = submission.get_item('submission_data')
    logger.debug("submission data: \n%s", pformat(submission_data))
    tag_map = CONF['tag_for_form_value']
    tag_slugs = (tag_map[field_name][field_value]
                 for field_name, field_value in submission_data
                 if field_name in tag_map and
                    field_value in tag_map[field_name])
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
    if submission is None:
        logger.warning("Submission fetch failed. API token is likely invalid.")
        return

    post_dataset = submission_to_tag_post(submission)

    for data in post_dataset:
        slug = data['tag']['slug']
        # r is a Requests Response object
        r_tagging = post_tagging(data)
        logger.debug("Response with %s", r_tagging.status_code)
        if r_tagging.status_code == requests.codes.created: # 201
            logger.info("Added tagging %s to user %s\n", data['tag'], data['user'])
        else:
            logger.debug("%s\n", r_tagging.json())


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


class QueueMixin:
    def __init__(self, *args, **kwargs):
        self.call_queue = IntervalCallQueue(CONF["worker_interval"])
        super().__init__(*args, **kwargs)

    def server_close(self):
        self.call_queue.stop()
        super().server_close()


class QueuingHTTPServer(QueueMixin, HTTPServer):
    pass


class QueuingUnixServer(QueueMixin, UnixStreamServer):
    def server_bind(self):
        try:
      	    os.unlink(self.server_address)
        except OSError:
            if os.path.exists(self.server_address):
                raise
        super().server_bind()
        os.chmod(self.server_address,int('766',8))
        return

    def get_request(self):
        request, client_address = self.socket.accept()
        # BaseHTTPRequestHandler expects a tuple with the client address at index 0
        # UnixStreamServer doesn't give an address, so we add a default
        client_address = ('UnixSocket',)
        return (request, client_address)

    def server_close(self):
        super().server_close()
        try:
            os.unlink(self.server_address)
        except OSError:
            if os.path.exists(self.server_address):
                raise


class APlusCourseHookHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if 'X-Forwarded-For' not in self.headers:
            logger.debug('Header X-Forwaded-For is missing')
            send_response(self, 400, msg='Header X-Forwarded-For not given')
            return
        addresses = [address.strip() for address in self.headers['X-Forwarded-For'].split(',')]
        if len(addresses) != CONF['num_proxies']:
            logger.debug('X-Forward-For implies %s proxies, arguments %s', len(addresses), CONF['num_proxies'])
            send_response(self, 400, msg="X-Forward-For doesn't match number of proxies")
            return
        self.client_address = (addresses[0],)
        parameters = parse_qs(urlsplit(self.path).query)
        content_length = int(self.headers['Content-Length'])
        post_data = parse_qs(self.rfile.read(content_length).decode('utf-8'))
        token = (post_data.get('token') or parameters.get('token') or (None,))[0]
        logger.info("HOOK with token %s", token)
        hook_token = CONF.get('hook_token')
        if hook_token and (not token or token != hook_token):
            logger.debug('Hook token doesn\'t match or was missing in POST')
            send_response(self, 401, msg='Bad auth token: missing or invalid')
            return
        reported_site = next(iter(post_data.get('site', ())), None)
        if not reported_site:
            logger.debug("Hook data doesn't contain a site")
            send_response(self, 400, msg="Bad request, missing site")
            return
        reported_site_parsed = urlsplit(reported_site)
        #base_url_netloc = urlsplit(CONF['base_url']).netloc 
        #reported_netloc = reported_site_parsed.netloc
        #if base_url_netloc != reported_netloc:
        #    logger.debug("base_url netloc in config %s doesn't match POST parameter 'site' %s netloc", 
        #                 base_url_netloc, reported_netloc)
        #    send_response(self, 400, msg="Base url given in parameter 'site' does not match config")
        #    return
        supposed_ips = get_url_ip_address_list(reported_site_parsed.hostname)
        client_ip = self.client_address[0]
        if client_ip not in supposed_ips: 
            logger.debug("Client ip %s doesn't match reported ips %s in POST body", client_ip, supposed_ips)
            send_response(self, 400, msg="Deceptive: client does not match POST parameter 'site' after resolve")
            return
        logger.debug(pformat(dict(post_data)))
        try:
            exercise_id = int(next(iter(post_data.get('exercise_id', ())), None))
            submission_id = int(next(iter(post_data.get('submission_id', ())), None))
        except (KeyError, ValueError, TypeError):
            logger.debug("Missing or invalid exercise_id or submission_id")
            send_response(self, 400, msg="Invalid or missing exercise_id or submission_id")
            return
        self.server.call_queue.schedule(add_tagging, exercise_id, submission_id)
        send_response(self, 204, msg="OK")


def sync_tags():
    usertags = get_usertags()
    if usertags is None:
        logger.warning("Usertag fetch failed. API token is likely invalid.")
        return
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
    loc = CONF['server_address']
    httpd = server_class(loc, handler_class)
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


CONF = {
    "hook_token":      "testing",
    "courses_url":     "/courses/",
    "exercises_url":   "/exercises/",
    "submissions_url": "/submissions/",
    "usertags_url":    "/usertags/",
    "taggings_url":    "/taggings/",
    "taggings_query":  "?tag_id=",
}

api = None
sess = None

def setup(conf_file):
    global api, sess

    with open(conf_file, "r") as f:
       CONF.update(json.load(f))

    api = AplusTokenClient(CONF['api_token'])
    api.set_base_url_from(CONF['base_url'])

    sess = requests.Session()
    logging.basicConfig()


def main():
    p = ArgumentParser()
    p.add_argument('-c', '--config', type=str, default='conf.json')
    p.add_argument('-v', '--verbose', action='count',
               help="Print more information, stackable")
    p.add_argument('-s', '--server', action='store_true', 
               help="Run the server")    
    p.add_argument('-u', '--unix',
               help="Run a Unix filesocket server instead of the HTTP one, supply path to socket")
    p.add_argument('-p', '--num_proxies', type=int, default=1,
               help="The number of proxies between A-plus and here (that set X-Forwaded-For)")
    p.add_argument('-b', '--batch', type=int,
               help="Run a batch job, go through tags from last N hours")
    args = p.parse_args()

    setup(args.config)

    logging.getLogger().setLevel(level=
        logging.WARNING if args.verbose == None else
        logging.INFO    if args.verbose == 1 else
        logging.DEBUG   if args.verbose == 2 else
        logging.DEBUG)

    sync_tags()

    did = ""
    if args.batch:
        logger.info("Running batch")
        do_batch(args.batch)
        did += "b"
    if args.server:
        logger.info("Running server")
        CONF['num_proxies'] = args.num_proxies
        if args.unix:
            CONF['server_address'] = args.unix.encode('utf-8')
            run_server(server_class=QueuingUnixServer)
        else:
            CONF['server_address'] = tuple(CONF['server_address'])
            run_server()
        did += "s"
    if did == "":
        logger.warning("No flags given")


if __name__ == '__main__':
    main()
