#!/bin/bash

get_full_path() {
    local pid="$1" method="$2"
    echo "PID: $pid"

    case $method in
        1)
            echo "Command: ls -l /proc/$pid/exe"
            # Get last field from ls output
            ls -l "/proc/$pid/exe" 2>/dev/null | awk '{print $NF}'
            ;;
        2)
            echo "Command: readlink -f /proc/$pid/exe"
            readlink -f "/proc/$pid/exe" 2>/dev/null
            ;;
        3)
            echo "Command: cat /proc/$pid/cmdline"
            # Multiple null-separated args, replace nulls with spaces, add newline at end
            cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' '; echo
            ;;
        *)
            echo "Invalid method choice."
            ;;
    esac
}

get_loaded_libs() {
    local pid="$1" method="$2"
    echo "PID: $pid"

    case $method in
        1)
            echo "Command: ls -l /proc/$pid/map_files/"
            ls -l "/proc/$pid/map_files/" 2>/dev/null | awk '{print $NF}' | grep '\.so' | sort -u
            ;;
        2)
            echo "Command: cat /proc/$pid/maps"
            awk '/\.so/{print $NF}' "/proc/$pid/maps" 2>/dev/null | sort -u
            ;;
        3)
            echo "Command: readlink -f /proc/$pid/map_files/*"
            readlink -f /proc/$pid/map_files/* 2>/dev/null | grep '\.so' | sort -u
            ;;
        *)
            echo "Invalid method choice."
            ;;
    esac
}

echo "Options:"
echo "1. Get full path of a process (PID)"
echo "2. Get all libraries loaded in memory (PID)"
read -p "Enter your choice: " choice

read -p "Enter the PID: " pid

# Validate numeric PID and existence directory of process
if [[ ! "$pid" =~ ^[0-9]+$ || ! -d "/proc/$pid" ]]; then
    echo "Invalid PID or process does not exist."
    exit 1
fi

case $choice in
    1)
        echo "Choose method to get full path:"
        echo "1. ls"
        echo "2. readlink"
        echo "3. cat"
        read -p "Enter your choice: " method
        get_full_path "$pid" "$method"
        ;;
    2)
        echo "Choose method to get loaded libraries:"
        echo "1. ls"
        echo "2. cat"
        echo "3. readlink"
        read -p "Enter your choice: " method
        get_loaded_libs "$pid" "$method"
        ;;
    *)
        echo "Invalid main choice."
        ;;
esac
