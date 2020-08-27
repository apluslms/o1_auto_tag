# o1_auto_tag

Python tool for automatically tagging users on the Aplus LMS platform.

Previously developed in:

* https://github.com/jparta/o1_auto_tag
* https://github.com/jrp6/o1_auto_tag

## Setup

1. Update conf.json
  - Set `hook_token` (suggestion: `openssl rand -hex 16`)
  - Get a teacher's (yours, preferrably) API token from the Aplus
    profile page, and set that as the `api_token`
  - Make sure `course_id` (course instance id in A+) and
    `exercise_ids` (BaseExercise ids in A+) are correct.
    The submissions in the defined exercises are used for automatic tagging.
  - Update tag mappings in `tag_for_form_value`.
    They map question and answer keys to the tag slugs.
    For example,

    ```
    "tag_for_form_value": {
        "languageskills": {
            "finnish": "fi",
            "swedish": "sv",
            "english": "en"
        }
    }
    ```

    corresponds to the quiz form field "languageskills" with input choices
    "finnish", "swedish" and "english". The answers are mapped to the tags with slugs
    "fi", "sv" and "en". The HTML form of the quiz could look like this:

    ```
    <label>My preferred language is:</label>
    <label>
      <input id="id_languageskills_0" name="languageskills" type="radio" value="finnish">
      Finnish
    </label>
    <label>
      <input id="id_languageskills_1" name="languageskills" type="radio" value="swedish">
      Swedish
    </label>
    <label>
      <input id="id_languageskills_2" name="languageskills" type="radio" value="english">
      English
    </label>
    ```
2. Set the post-grading hook in A+ to the corresponding course instance (`/admin/course/coursehook/`)
  - Hook url: set the IP and port of the script server, and
    add the configured hook token as a parameter (`?token=`)

## Usage

1. Make sure your environment is up to date (Python 3.5+ and `pip install -r requirements.txt`).
2. Run the script using flags -v, -s and -b. These stand for --verbose, --server and --batch.
  - First, missing tags (comparison between Aplus and the "tag_for_form_value" in conf.json)
    are created in Aplus. The tags should be edited manually in A+ because
    the automatically created tag names are not very human readable.
    Do not edit the tag slugs because they are used in the mapping of submissions to tags.
    **Warning**: if `tag_for_form_value` maps several choices to the same tag slug,
    then o1_auto_tag will create the same tag multiple times in A+.
    This results in duplicate tags that have random characters appended to the end of the tag slug.
    A+ API creates a new tag even if the given slug already exists, but
    A+ makes the new slug unique by appending random characters to the end.
    This problem only occurs on the first run when the tag slugs do not exist in A+.
    Some day, o1_auto_tag could be fixed so that it does not try to create
    the same tag slug multiple times in A+ (in the `sync_tags` function).
  - Batch is run through. The flag takes as its only argument a count of hours, 
    indicating how far back the script should look for submissions to create taggings based on.
  - Server is run forever. It receives hooks from Aplus on exercise submissions
    and creates taggings based on the submitted form contents.

## More

There are other flags:

* `-c`, `--config` configuration file path conf.json
* `-u`, `--unix` unix socket path.
  Unix sockets can be used, but they cause a broken pipe error relatively often for an unknown reason.
* `-p`, `--num-proxies` the number of proxies that set the X-Forwarded-For header.
  The X-Forwarded-For header is needed to check the original sender, and
  the number of proxies tells us if we should trust the header.

Example location definition in Nginx HTTP server configuration:

```
location /autotag/o1/ {
    include proxy_params;
    proxy_set_header X-Forwarded-Prefix /autotag/o1/;
    proxy_pass http://127.0.0.1:5002/;
    proxy_redirect off;
    proxy_http_version 1.1;
}
```

Example systemd configuration for running the o1_auto_tag server
(the app is installed in `/srv/autotag/o1_auto_tag` and
the Python virtual environment is in `/srv/autotag/venv`):

```
[Unit]
Description=WWW App - Autotag o1
PartOf=nginx.service

[Service]
User=autotag
Group=nogroup
SyslogIdentifier=autotag-o1
StandardOutput=syslog
StandardError=syslog
WorkingDirectory=/srv/autotag/o1_auto_tag
Environment="PATH=/usr/bin:/bin"
Environment="PYTHONPATH=/srv/autotag/o1_auto_tag"
ExecStart=/srv/autotag/venv/bin/python3 o1_auto_tag.py -c o1.json -p 1 -b 1 -s -v
ExecStop=/bin/kill -s TERM $MAINPID
RestartSec=15
Restart=always

[Install]
WantedBy=multi-user.target
```

This example uses `"server_address": ["127.0.0.1", 5002]` in `o1.json`.

