#!/bin/bash -x
ansible-playbook --connection=local --inventory 127.0.0.1, site.yml
