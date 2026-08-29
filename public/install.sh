#!/bin/sh
set -eu

printf '%s\n' \
  'The legacy Penumbra Gate installer at /install.sh has been withdrawn.' \
  'It referenced commands and build steps that the current Gate release does not provide.' \
  'No installation or system change was attempted.' \
  '' \
  'Review the current, versioned instructions before installing:' \
  '  https://penumbraforge.com/gate/wiki/getting-started/' \
  '  https://github.com/penumbraforge/gate' >&2

exit 1
