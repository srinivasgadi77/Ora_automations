rpm -qa --last kernel kernel-uek  >/var/tmp/before_kernel_delete

k_cnt=$(rpm -qa --last kernel kernel-uek | wc -l)

if [[ $k_cnt > 1 ]]
then 
  echo "more tha one deleting"
  rpm -qa --last kernel kernel-uek | tail -1 | awk '{print $1}' | xargs yum remove -y
else
  echo "One kernle, cent delete"
fi

rpm -qa --last kernel kernel-uek  >/var/tmp/after_kernel_delete
