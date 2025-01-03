Given a list of paths to `.csv` files from `/cat/log/fwnua/machine/`
this program counts how many users are online at any point in time
and outputs pairs of `<time changed>, <new count value>`.

Sessions shorter than 1 minute or longer than 1 day are filtered out.
Malformed sessions with no known start or no known end are identified and
stored, but currently dropped before counting.  
Sessions with an end dated earlier in time than their start (apparent time-travel)
are also identified, stored, and later dropped, as well as "valid" sessions
that overlap with previously seen sessions due to a preceding time-travel.
