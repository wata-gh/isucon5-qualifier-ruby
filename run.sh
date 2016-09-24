#!/bin/sh

export ISUCON5_DB_USER=isucon
export ISUCON5_DB_PASSWORD=isucon
bundle exec unicorn -c unicorn_config.rb -E production
