DRC RE scripts
==============

A set of scripts to help reverse engineering DRC stuff.

Protocol related scripts
------------------------

* vstrm_parse.py: shows some information about a vstrm data file and decodes it
  to a .h264 file.
* drc_parse.py: shows overall information about all protocols.
* drh-known-devices.py: presents human-readable version of the wifi configuration stored on DRH flash.

IDA/firmware related scripts
----------------------------

* Load the file in IDA.
  * Currently only compatible with DRC LVC_ binary.
  * Load as ARM Little Endian ARMv5TEJ.
* Run explore-file.py (creates segments, marks things as data/code)
* Run find-uitron-apis.py (renames the uITRON functions)
* Run name-funcs-by-src-str.py (renames the functions using the source code
  file information).
