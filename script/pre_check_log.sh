log_file=$(ls -lrt /var/tmp/pre_*.log | tail -1 | awk '{print $9}' )
cat $log_file | tr '\n' ','
