#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

if [ -e "$SCRIPT_DIR/requirements.txt" ];then
	pip install -r "$SCRIPT_DIR/requirements.txt"
fi

install "$SCRIPT_DIR/syscall_searcher.py" "$HOME/.local/bin"
install "$SCRIPT_DIR/syscall_sigs.sh" "$HOME/.local/bin"
