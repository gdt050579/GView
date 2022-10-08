GView configuration file
=================================

GView is configured via ``GView.ini`` file (that should be located next to GView executable). If the file is missing, running a simple ``GView reset`` command from the CLI should restore it.

The following section should be seen in a ``GView.ini`` file:

* ``[GView]`` - a section with the general configuration for GView. Tipically it contains associated key for changing the view, cache size, etc.
* ``[AppCUI]`` - a section with the general configuration for AppCUI framework (color, frontend, etc)
* ``[Type.<XXX>]`` - various sections that describe characteristics of each supported type in GView
* ``[View.<xxx>]`` - various section for each smart view

Types
-----

A ``[Type.xxx]``` section usually contains the following:

* a `Description` field that explains the type of the plugin
* a `Extension` field that can be a simple string or a list of strings containing the list of extensions associated with this field.


  ..  code-block:: ini

      Extension = exe
      
  or
  
  ..  code-block:: ini

      Extension = ["h","hpp","cpp","c"]
      
      
* a ``Pattern`` field that provides some rules that if match the entire plugin is loaded in memory and checked against the content. This ensures quick validation of the content so that not all plugins are loaded in memory.
  A pattern is a string with the following format: **rule**:`parameters`, where **rule** can be one of the following:
  
+------------------+---------+--------------------------------------------------+--------------------------------+
| Rule             | Type    | Usage                                            | Example                        |
+==================+=========+==================================================+================================+
| magic            | Binary  | Identifies a binary magic from the start of the  | **magic**:FF 20 30             |
|                  | Files   | file. A magic must be foollowed by a list of hex |                                |
|                  |         | values separated with spaces                     |                                |
+------------------+---------+--------------------------------------------------+--------------------------------+
| startswith       | Text    | Checks if a file starts with a specific text     | **startswith**:#include        |
|                  | Files   |                                                  |                                |
+------------------+---------+--------------------------------------------------+--------------------------------+
| linestartswith   | Text    | Checks if one of the first 10 lines from a text  | **linestartswith**:#define     |
|                  | Files   | file starts with a specific text                 |                                |
+------------------+---------+--------------------------------------------------+--------------------------------+

