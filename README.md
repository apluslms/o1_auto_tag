# o1_auto_tag
Python tool for automatically tagging users on the Aplus LMS platform.

## Setup
1. Update conf.json
  - Set `hook_token` (suggestion: `openssl rand -hex 16`)
  - Get a teacher's (yours, preferrably) API token from the Aplus
    profile page, and set that as the `api_token`
  - Make sure `course_id` and `exercise_ids` are correct
  - Update tag mappings in `tag_for_form_value`
2. Set hooks in Aplus (/admin/course/coursehook/)
  - Hook url: set the IP and port of the script server, and add the configured hook token as a parameter (?token=)

## Usage
1. Make sure your environment is up to date (Python 3.5+ and `pip install -r requirements.txt`).
2. Run the script using flags -v, -s and -b. These stand for --verbose, --server and --batch.
  - First, missing tags (comparison between Aplus and conf) are created in Aplus. 
    These are not that informative and should be edited.
  - Batch is run through. The flag takes as its only argument a count of hours, 
    indicating how far back the script should look for submissions to create taggings based on.
  - Server is run forever. It receives hooks from Aplus on submission of exercises, 
    and creates taggings based on the form contents.
    
