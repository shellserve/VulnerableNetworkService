#!/bin/bash

curl -s -u $1:none -i -X POST -H 'Content-Type: application/json' -d '{"service":"'$2'","password":"'$2'"}' http://127.0.0.1:5000/password/set
