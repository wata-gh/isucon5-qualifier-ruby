#!/bin/sh

set -x
mysqldump -uisucon -pisucon isucon5q raw_http_logs raw_sql_logs > raw_logs.dump
rm -f raw_logs.dump.gz
gzip raw_logs.dump

