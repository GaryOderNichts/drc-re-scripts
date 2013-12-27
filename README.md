DRC RE scripts
==============

A set of scripts to help reverse engineering DRC stuff.

Protocol related scripts
------------------------

* vstrm_parse.py: shows some information about a vstrm data file and decodes it
  to a .h264 file.

IDA/firwmare related scripts
----------------------------

* Load the file in IDA
* Run explore-file.py (creates segments, marks things as data/code)
* Run find-uitron-apis.py (renames the uITRON functions)
* Run name-funcs-by-src-str.py (renames the functions using the source code
  file information).
