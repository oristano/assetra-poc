#!/bin/sh
set -e

if ! steampipe plugin list 2>/dev/null | grep -q "^csv"; then
    echo "Installing steampipe csv plugin..."
    steampipe plugin install csv
fi

exec steampipe service start \
    --foreground \
    --database-listen=network \
    --database-password=steampipe
