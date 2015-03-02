This directory contains two sets of data:

  - A collection of standalone, small starting files for a variety of common
    data formats, including images, archives, and so on. You can use them
    directly with the -i option when running afl-fuzz.

  - A smaller set of fuzzing dictionaries, provided in _extras/ subdirectory and
    to be used with the -x option, as discussed in the README.

The first data set probably requires no special discussion. The other provides
good examples of syntax tokens both for binary files (e.g., PNG, TIFF) and for
text-based formats (XML, SQL).

Somewhat predictably, when the syntax tokens are around 1-2 bytes long (as is
the case for GIF and JPEG), the benefits of fuzzing with a dictionary are
fairly modest and the ultimate coverage does not differ much. For data formats
that rely on longer atomically checked tokens (e.g., 4-byte PNG section
headers), the gains are are much more profound.

Oh, by the way: contributions to both data sets are very welcome. For the
initial samples, my current "most wanted" list includes:

  - JBIG,
  - Ogg Vorbis,
  - Ogg Theora,
  - MP3,
  - AAC,
  - WebM,
  - Small JPEG with ICC (LCMS),
  - Small font (Freetype).
