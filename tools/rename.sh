for f in *; do
    echo "$f"
    # test -f "$f" &&
    new_file=`tr "$f" '[:lower:]'`
    echo "$new_file"
    # echo mv "$f" "$new_file"
done