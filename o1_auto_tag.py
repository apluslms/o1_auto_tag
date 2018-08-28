#!/usr/bin/env python3
import logging
from threading import Timer
from aplus_client.client import AplusTokenClient
from argparse import ArgumentParser
from itertools import chain

CONFIG = {
    'base_url': 'http://localhost:8000/api/v2/',
    'courses_url': '/courses/',
    'exercises_url': '/exercises/',
    'submissions_url': '/submissions/',
    'taggings_url': '/taggings/',
    'taggings_query': '?tag_id=',
    'course_id': 3,
    'exercise_ids': {2262, 2263},
    'timer_interval': 15.0 * 60,
}

tag_for_form_value = {
    'kielitaito': {
        'suomi': { 'id': 42, 'slug': 'fi' },
        'ruotsi': { 'id': 44, 'slug': 'sv' },
        'englanti': { 'id': 43, 'slug': 'en' },
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

def get_from_api(url_format, ids):
    urls = [url_format.format(**CONFIG, id=id) for id in ids]
    responses = [api.load_data(url) for url in urls]
    return frozenset(chain(*responses))

def get_submissions():
    return get_from_api('{exercises_url}{id}{submissions_url}',
                        CONFIG['exercise_ids'])

def get_taggings():
    return get_from_api(
        '{courses_url}{course_id}{taggings_url}{taggings_query}{id}',
        (tag['id']
         for field in tag_for_form_value.values()
         for tag in field.values()))

def main():
    Timer(CONFIG['timer_interval'], main).start()
    submissions = get_submissions()
    taggings = get_taggings()
    tagged_user_ids = {tag['user']['id'] for tag in taggings}

    # Known bug:  if someone/something else has already added a tagging that may be
    #             given by this excercise, nothing will be done.
    # Workaround: assign the specified tags using this script *ONLY*
    submissions_not_tagged = (submission
                              for submission in submissions
                              if not tagged_user_ids.issuperset(
                                      submitter['id']
                                      for submitter in submission['submitters']))

    for submission in submissions_not_tagged:
        submission_data = submission['submission_data']
        tag_slugs = (tag_for_form_value[field[0]][field[1]]['slug']
                     for field in submission_data
                     if field[0] in tag_for_form_value)
        user_ids = (submitter['id'] for submitter in submission['submitters'])
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

if __name__ == '__main__':
    main()
